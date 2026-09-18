package web

import (
	"crypto/tls"
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"honeygo/internal/css"
	"honeygo/internal/db"
	"honeygo/internal/geoip"
	"honeygo/internal/misp"
	"honeygo/internal/recon"
	"honeygo/internal/syslog"
	"honeygo/internal/tlsutil"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Version = "v0.5.8"

//go:embed static/*
var staticFiles embed.FS

type cachedResponse struct {
	data      []byte
	timestamp time.Time
}

var (
	apiCacheMu sync.RWMutex
	apiCache   = make(map[string]cachedResponse)
)

func getCachedAPI(key string, ttl time.Duration) ([]byte, bool) {
	apiCacheMu.RLock()
	defer apiCacheMu.RUnlock()
	if c, ok := apiCache[key]; ok && time.Since(c.timestamp) < ttl {
		return c.data, true
	}
	return nil, false
}

func setCachedAPI(key string, data []byte) {
	apiCacheMu.Lock()
	defer apiCacheMu.Unlock()
	apiCache[key] = cachedResponse{data: data, timestamp: time.Now()}
}

func ClearAPICache() {
	apiCacheMu.Lock()
	defer apiCacheMu.Unlock()
	apiCache = make(map[string]cachedResponse)
	db.ClearCorrelationCache()
}

type ServiceStatusInfo struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Status   string `json:"status"`
	Isolated bool   `json:"isolated"`
}

type WebServer struct {
	port           int
	getActiveCount func() int
	getServices    func() []ServiceStatusInfo
	server         *http.Server
	listener       net.Listener
	geo            *geoip.Resolver

	sslEnabled bool
	tlsConfig  *tls.Config
}

func NewWebServer(port int, getActiveCount func() int, getServices ...func() []ServiceStatusInfo) *WebServer {
	var gs func() []ServiceStatusInfo
	if len(getServices) > 0 {
		gs = getServices[0]
	}
	ws := &WebServer{
		port:           port,
		getActiveCount: getActiveCount,
		getServices:    gs,
		geo:            geoip.NewResolver(),
	}
	db.GeoResolver = ws.geo
	return ws
}

func (ws *WebServer) Port() int {
	return ws.port
}

func (ws *WebServer) SetLogger(w io.Writer) {
	css.SetLogger(w)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func sanitizeInput(s string) string {
	if unescaped, err := url.PathUnescape(s); err == nil {
		s = unescaped
	}
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r != 0 && (r >= 32 || r == '\t' || r == '\n' || r == '\r') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sanitizeCSVField(s string) string {
	if len(s) > 0 {
		switch s[0] {
		case '=', '+', '-', '@', '\t', '\r':
			return "'" + s
		}
	}
	return s
}

func (ws *WebServer) GetMux() *http.ServeMux {
	mux := http.NewServeMux()

	// Static files with no-cache and security headers
	staticFS, _ := fs.Sub(staticFiles, "static")
	fileServer := http.FileServer(http.FS(staticFS))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		fileServer.ServeHTTP(w, r)
	})

	// API Endpoints with no-cache and security headers
	api := func(path string, handler http.HandlerFunc) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			setSecurityHeaders(w)
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			handler(w, r)
		})
	}

	api("/api/stats", ws.handleStats)
	api("/api/credentials", ws.handleCredentials)
	api("/api/analytics", ws.handleAnalytics)
	api("/api/analytics/correlations", ws.handleCorrelations)
	api("/api/analytics/asncategory", ws.handleASNCategoryDetails)
	api("/api/host/", ws.handleHostDetails)
	api("/api/scans", ws.handleScans)
	api("/api/requests/detail", ws.handleRequestDetail)
	api("/api/requests/download", ws.handleDownloadRequest)
	api("/api/commands", ws.handleCommands)
	api("/api/ics", ws.handleICS)
	api("/api/logs/export", ws.handleExportLogs)
	api("/api/country/", ws.handleCountryDetails)
	api("/api/system/logs", ws.handleSystemLogs)

	// Reconnaissance & Threat Infrastructure Endpoints
	api("/api/recon", ws.handleReconList)
	api("/api/recon/target", ws.handleReconTarget)
	api("/api/recon/scan", ws.handleReconScan)
	api("/api/recon/add", ws.handleReconAddTarget)
	api("/api/recon/canary", ws.handleReconAddCanary)
	api("/api/recon/config", ws.handleReconConfig)

	// MISP Integration & Monitoring Endpoints
	api("/api/misp/status", ws.handleMISPStatus)
	api("/api/misp/config", ws.handleMISPConfig)
	api("/api/misp/test", ws.handleMISPTest)
	api("/api/misp/canary", ws.handleMISPCanary)
	api("/api/misp/events", ws.handleMISPEvents)

	// Central Storage Server (CSS) & Feed endpoints
	css.RegisterRoutes(mux)
	return mux
}

// EnableSSL configures SSL/TLS encryption for the WebServer using certificates in ./certs/.
// If certificates are not found in ./certs/, it returns an error.
func (ws *WebServer) EnableSSL(dir ...string) error {
	certDir := "certs"
	if len(dir) > 0 && dir[0] != "" {
		certDir = dir[0]
	}
	cert, err := tlsutil.LoadCertsFromDir(certDir)
	if err != nil {
		return err
	}
	ws.sslEnabled = true
	ws.tlsConfig = tlsutil.NewServerTLSConfig(cert)
	return nil
}

// EnableSSLWithCert configures SSL/TLS encryption using a provided certificate (useful for unit tests).
func (ws *WebServer) EnableSSLWithCert(cert tls.Certificate) {
	ws.sslEnabled = true
	ws.tlsConfig = tlsutil.NewServerTLSConfig(cert)
}

// DisableSSL disables SSL/TLS encryption, reverting to plain HTTP.
func (ws *WebServer) DisableSSL() {
	ws.sslEnabled = false
	ws.tlsConfig = nil
}

// IsSSLEnabled returns whether SSL/TLS encryption is active.
func (ws *WebServer) IsSSLEnabled() bool {
	return ws.sslEnabled
}

func (ws *WebServer) Start() error {
	mux := ws.GetMux()

	ws.server = &http.Server{
		Addr:    fmt.Sprintf(":%d", ws.port),
		Handler: mux,
	}

	ln, err := net.Listen("tcp4", ws.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to bind port %d: %w", ws.port, err)
	}

	if ws.sslEnabled {
		if ws.tlsConfig == nil {
			if err := ws.EnableSSL(); err != nil {
				_ = ln.Close()
				return fmt.Errorf("failed to enable SSL on web server: %w", err)
			}
		}
		ln = tls.NewListener(ln, ws.tlsConfig)
	}
	ws.listener = ln

	// Start background GeoIP resolution for existing/incoming records
	ws.geo.StartAutoResolver()

	go func() {
		if err := ws.server.Serve(ln); err != nil && err != http.ErrServerClosed {
			proto := "HTTP"
			if ws.sslEnabled {
				proto = "HTTPS"
			}
			fmt.Printf("\n[!] WebUI %s Server Error: %v\n", proto, err)
		}
	}()

	return nil
}

func (ws *WebServer) Stop() error {
	if ws.geo != nil {
		ws.geo.Close()
	}
	if ws.listener != nil {
		_ = ws.listener.Close()
	}
	if ws.server != nil {
		return ws.server.Close()
	}
	return nil
}

func (ws *WebServer) handleStats(w http.ResponseWriter, r *http.Request) {
	sensor := r.URL.Query().Get("sensor")
	cacheKey := "stats:" + sensor
	if data, ok := getCachedAPI(cacheKey, 10*time.Second); ok {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	var totalAttempts int64
	attemptsQuery := db.DB.Model(&db.Attempt{})
	attemptsQuery = db.ApplySensorFilter(attemptsQuery, sensor)
	attemptsQuery.Count(&totalAttempts)

	var totalCreds int64
	credsQuery := db.DB.Model(&db.Credential{})
	credsQuery = db.ApplySensorFilter(credsQuery, sensor)
	credsQuery.Count(&totalCreds)

	sensors, _ := db.GetSensorsList()
	totalSensorsCount := len(sensors)

	activeSensorsCount := 0
	for _, s := range sensors {
		if s.Status == "Active" || s.Status == "Online" {
			activeSensorsCount++
		}
	}

	connectedSensorsCount := activeSensorsCount
	if sensor != "" && sensor != "all" {
		foundActive := false
		for _, s := range sensors {
			if s.SensorID == sensor && (s.Status == "Active" || s.Status == "Online") {
				foundActive = true
				break
			}
		}
		if foundActive {
			connectedSensorsCount = 1
		} else {
			connectedSensorsCount = 0
		}
	} else if !css.IsCSSServerRunning() && !css.IsSensorMode() && totalSensorsCount == 0 {
		connectedSensorsCount = 1
		totalSensorsCount = 1
	}

	var servicesList []ServiceStatusInfo
	seen := make(map[string]bool)

	if sensor == "" || sensor == "all" {
		if ws.getServices != nil {
			for _, s := range ws.getServices() {
				key := fmt.Sprintf("%s:%d", s.Protocol, s.Port)
				if !seen[key] {
					seen[key] = true
					servicesList = append(servicesList, s)
				}
			}
		}
		for _, s := range db.GetSensorServices("all") {
			key := fmt.Sprintf("%s:%d", s.Protocol, s.Port)
			if !seen[key] {
				seen[key] = true
				servicesList = append(servicesList, ServiceStatusInfo{
					Protocol: s.Protocol,
					Port:     s.Port,
					Status:   s.Status,
					Isolated: s.Isolated,
				})
			}
		}
	} else if sensor == "local" || sensor == db.GetActiveSensorID() {
		if ws.getServices != nil {
			servicesList = ws.getServices()
		}
	} else {
		// Specific remote sensor
		for _, s := range db.GetSensorServices(sensor) {
			servicesList = append(servicesList, ServiceStatusInfo{
				Protocol: s.Protocol,
				Port:     s.Port,
				Status:   s.Status,
				Isolated: s.Isolated,
			})
		}
		if len(servicesList) == 0 && ws.getServices != nil && (sensor == "local" || sensor == db.GetActiveSensorID()) {
			servicesList = ws.getServices()
		}
	}

	activeCount := 0
	for _, s := range servicesList {
		if s.Status == "Running" || s.Status == "active" {
			activeCount++
		}
	}

	respObj := map[string]interface{}{
		"version":                  Version,
		"total_attempts":           totalAttempts,
		"total_credentials":        totalCreds,
		"connected_sensors_count":  connectedSensorsCount,
		"total_sensors_in_cluster": totalSensorsCount,
		"active_protocols_count":   activeCount,
		"selected_sensor":          sensor,
		"services":                 servicesList,
	}

	if data, err := json.Marshal(respObj); err == nil {
		setCachedAPI(cacheKey, data)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respObj)
}

func (ws *WebServer) handleCredentials(w http.ResponseWriter, r *http.Request) {
	sensor := sanitizeInput(r.URL.Query().Get("sensor"))
	q := sanitizeInput(r.URL.Query().Get("q"))
	if q == "" {
		q = sanitizeInput(r.URL.Query().Get("search"))
	}
	password := sanitizeInput(r.URL.Query().Get("password"))
	username := sanitizeInput(r.URL.Query().Get("username"))
	host := sanitizeInput(r.URL.Query().Get("host"))
	if host == "" {
		host = sanitizeInput(r.URL.Query().Get("ip"))
	}
	protocol := sanitizeInput(r.URL.Query().Get("protocol"))
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))

	query := db.DB.Model(&db.Credential{}).Order("created_at desc")
	query = db.ApplySensorFilter(query, sensor)
	if q != "" {
		qLower := "%" + strings.ToLower(q) + "%"
		query = query.Where(
			"LOWER(remote_ip) LIKE ? OR LOWER(username) LIKE ? OR LOWER(password) LIKE ? OR LOWER(protocol) LIKE ? OR LOWER(country_name) LIKE ? OR LOWER(country_code) LIKE ? OR LOWER(asn) LIKE ? OR LOWER(as_name) LIKE ?",
			qLower, qLower, qLower, qLower, qLower, qLower, qLower, qLower,
		)
	}
	if password != "" {
		query = query.Where("LOWER(password) LIKE ?", "%"+strings.ToLower(password)+"%")
	}
	if username != "" {
		query = query.Where("LOWER(username) LIKE ?", "%"+strings.ToLower(username)+"%")
	}
	if host != "" {
		query = query.Where("LOWER(remote_ip) LIKE ?", "%"+strings.ToLower(host)+"%")
	}
	if protocol != "" {
		query = query.Where("LOWER(protocol) = ?", strings.ToLower(protocol))
	}

	if format == "csv" {
		var creds []db.Credential
		if err := query.Find(&creds).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tsStr := time.Now().Format("20060102_150405")
		filename := fmt.Sprintf("honeygo_credentials_%s.csv", tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"Timestamp", "Sensor", "Protocol", "Country Code", "Country Name", "ASN", "AS Name", "Remote IP", "Username", "Password"})
		for _, c := range creds {
			_ = cw.Write([]string{
				c.CreatedAt.Format("2006-01-02 15:04:05"),
				sanitizeCSVField(c.SensorID),
				sanitizeCSVField(c.Protocol),
				sanitizeCSVField(c.CountryCode),
				sanitizeCSVField(c.CountryName),
				sanitizeCSVField(c.ASN),
				sanitizeCSVField(c.ASName),
				sanitizeCSVField(c.RemoteIP),
				sanitizeCSVField(c.Username),
				sanitizeCSVField(c.Password),
			})
		}
		cw.Flush()
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")

	isPaginated := pageStr != "" || r.URL.Query().Get("paginated") == "true"
	if isPaginated {
		page := 1
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
		limit := 25
		if limitStr == "all" {
			limit = 0
		} else if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}

		var total int64
		query.Count(&total)

		pagedQuery := query
		if limit > 0 {
			offset := (page - 1) * limit
			pagedQuery = pagedQuery.Offset(offset).Limit(limit)
		}

		var creds []db.Credential
		if err := pagedQuery.Find(&creds).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		totalPages := 1
		if limit > 0 && total > 0 {
			totalPages = int((total + int64(limit) - 1) / int64(limit))
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"total":       total,
			"page":        page,
			"page_size":   limit,
			"total_pages": totalPages,
			"credentials": creds,
		})
		return
	}

	cacheKey := fmt.Sprintf("creds:%s:%s:%s:%s:%s:%s", sensor, q, password, username, host, protocol)
	if data, ok := getCachedAPI(cacheKey, 10*time.Second); ok {
		w.Write(data)
		return
	}

	var creds []db.Credential
	if err := query.Find(&creds).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if data, err := json.Marshal(creds); err == nil {
		setCachedAPI(cacheKey, data)
		w.Write(data)
		return
	}

	json.NewEncoder(w).Encode(creds)
}

func (ws *WebServer) handleAnalytics(w http.ResponseWriter, r *http.Request) {
	sensor := r.URL.Query().Get("sensor")
	cacheKey := "analytics:" + sensor
	if data, ok := getCachedAPI(cacheKey, 15*time.Second); ok {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	passwords, _ := db.GetTopPasswordsFilter(10, sensor)
	protocols, _ := db.GetProtocolStatsFilter(sensor)
	countries, _ := db.GetTopCountriesFilter(10, sensor)
	hosts, _ := db.GetTopHostsFilter(10, sensor)
	usernames, _ := db.GetTopUsernamesByProtocolFilter(10, sensor)
	netblocks, _ := db.GetTopNetblockOwnersFilter(10, sensor)
	topProtoByCountry, _ := db.GetTopProtocolByCountryFilter(10, sensor)
	asnCompanyTypes, _ := db.GetASNCompanyTypeStatsFilter(sensor)

	respObj := map[string]interface{}{
		"passwords":               passwords,
		"protocols":               protocols,
		"countries":               countries,
		"hosts":                   hosts,
		"usernames":               usernames,
		"netblocks":               netblocks,
		"top_protocol_by_country": topProtoByCountry,
		"asn_company_types":       asnCompanyTypes,
	}

	// Pre-warm top hosts into in-memory cache in background
	go ws.prewarmTopHosts(hosts, sensor)

	if data, err := json.Marshal(respObj); err == nil {
		setCachedAPI(cacheKey, data)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respObj)
}

func (ws *WebServer) handleASNCategoryDetails(w http.ResponseWriter, r *http.Request) {
	cat := sanitizeInput(r.URL.Query().Get("category"))
	sensor := sanitizeInput(r.URL.Query().Get("sensor"))

	hosts, err := db.GetASNCategoryHostsFilter(cat, sensor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"category": cat,
		"total":    len(hosts),
		"hosts":    hosts,
	})
}

func (ws *WebServer) handleHostDetails(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Type", "application/json")

	rawIP := strings.TrimPrefix(r.URL.Path, "/api/host/")
	ip := sanitizeInput(rawIP)
	if ip == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	sensor := sanitizeInput(r.URL.Query().Get("sensor"))
	cacheKey := fmt.Sprintf("host:%s:%s", ip, sensor)
	if data, ok := getCachedAPI(cacheKey, 30*time.Second); ok {
		w.Write(data)
		return
	}

	data, err := ws.buildHostDetailsJSON(ip, sensor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	setCachedAPI(cacheKey, data)
	w.Write(data)
}

func (ws *WebServer) prewarmTopHosts(hosts []db.HostStat, sensor string) {
	for _, h := range hosts {
		if h.RemoteIP == "" {
			continue
		}
		cacheKey := fmt.Sprintf("host:%s:%s", h.RemoteIP, sensor)
		if _, ok := getCachedAPI(cacheKey, 30*time.Second); ok {
			continue
		}
		data, err := ws.buildHostDetailsJSON(h.RemoteIP, sensor)
		if err == nil && len(data) > 0 {
			setCachedAPI(cacheKey, data)
		}
	}
}

func (ws *WebServer) buildHostDetailsJSON(ip, sensor string) ([]byte, error) {
	var attemptsCount int64
	attemptsQuery := db.DB.Model(&db.Attempt{}).Where("remote_ip = ?", ip)
	attemptsQuery = db.ApplySensorFilter(attemptsQuery, sensor)
	attemptsQuery.Count(&attemptsCount)

	var creds []db.Credential
	credsQuery := db.DB.Model(&db.Credential{}).Where("remote_ip = ?", ip)
	credsQuery = db.ApplySensorFilter(credsQuery, sensor)
	credsQuery.Order("created_at desc").Limit(200).Find(&creds)

	var commands []db.Command
	cmdsQuery := db.DB.Model(&db.Command{}).Where("remote_ip = ?", ip)
	cmdsQuery = db.ApplySensorFilter(cmdsQuery, sensor)
	cmdsQuery.Order("created_at desc").Limit(200).Find(&commands)

	var allAttempts []db.Attempt
	recentQuery := db.DB.Model(&db.Attempt{}).Where("remote_ip = ?", ip)
	recentQuery = db.ApplySensorFilter(recentQuery, sensor)
	recentQuery.Order("created_at desc").Limit(200).Find(&allAttempts)

	var webAttempts []db.Attempt
	webQuery := db.DB.Model(&db.Attempt{}).Where("remote_ip = ? AND protocol = ?", ip, "web")
	webQuery = db.ApplySensorFilter(webQuery, sensor)
	webQuery.Order("created_at desc").Limit(200).Find(&webAttempts)

	type HostWebReq struct {
		ID            uint      `json:"id"`
		CreatedAt     time.Time `json:"created_at"`
		SensorID      string    `json:"sensor_id"`
		Port          int       `json:"port"`
		MethodPath    string    `json:"method_path"`
		UserAgent     string    `json:"user_agent"`
		CustomHeaders string    `json:"custom_headers"`
		SizeBytes     int       `json:"size_bytes"`
	}
	webReqs := make([]HostWebReq, 0, len(webAttempts))
	for _, wa := range webAttempts {
		methodPath, userAgent, customHeaders := parseRawHTTP(wa.RawData)
		sensorID := wa.SensorID
		if sensorID == "" {
			sensorID = "local"
		}
		webReqs = append(webReqs, HostWebReq{
			ID:            wa.ID,
			CreatedAt:     wa.CreatedAt,
			SensorID:      sensorID,
			Port:          wa.Port,
			MethodPath:    methodPath,
			UserAgent:     userAgent,
			CustomHeaders: customHeaders,
			SizeBytes:     len(wa.RawData),
		})
	}

	// Build Secondary Attack Infrastructure & Payload Mentions
	type SecondaryAttackMention struct {
		CreatedAt   time.Time `json:"created_at"`
		SensorID    string    `json:"sensor_id"`
		Protocol    string    `json:"protocol"`
		AttackerIP  string    `json:"attacker_ip"`  // Primary attacker host IP that entered the command
		FullCommand string    `json:"full_command"` // Complete un-truncated command payload
		SourceType  string    `json:"source_type"`
	}

	var mentions []SecondaryAttackMention
	seenMention := make(map[uint]bool)

	// 1. Query commands where command text contains this IP (bounded to 100)
	var mentionCmds []db.Command
	mQuery := db.DB.Model(&db.Command{}).Where("command LIKE ?", "%"+ip+"%")
	mQuery = db.ApplySensorFilter(mQuery, sensor)
	mQuery.Order("created_at desc").Limit(100).Find(&mentionCmds)

	for _, mc := range mentionCmds {
		if !seenMention[mc.ID] {
			seenMention[mc.ID] = true
			mentions = append(mentions, SecondaryAttackMention{
				CreatedAt:   mc.CreatedAt,
				SensorID:    mc.SensorID,
				Protocol:    mc.Protocol,
				AttackerIP:  mc.RemoteIP,
				FullCommand: mc.Command,
				SourceType:  "c2_dropper",
			})
		}
	}

	// 2. If viewing host that typed secondary script commands (bounded to 100)
	var ownDropperCmds []db.Command
	oQuery := db.DB.Model(&db.Command{}).Where("remote_ip = ? AND (command LIKE '%wget%' OR command LIKE '%curl%' OR command LIKE '%tftp%' OR command LIKE '%ftpget%' OR command LIKE '%http%' OR command LIKE '%.sh%')", ip)
	oQuery = db.ApplySensorFilter(oQuery, sensor)
	oQuery.Order("created_at desc").Limit(100).Find(&ownDropperCmds)

	for _, oc := range ownDropperCmds {
		if !seenMention[oc.ID] {
			seenMention[oc.ID] = true
			mentions = append(mentions, SecondaryAttackMention{
				CreatedAt:   oc.CreatedAt,
				SensorID:    oc.SensorID,
				Protocol:    oc.Protocol,
				AttackerIP:  oc.RemoteIP,
				FullCommand: oc.Command,
				SourceType:  "c2_dropper",
			})
		}
	}

	sort.Slice(mentions, func(i, j int) bool {
		return mentions[i].CreatedAt.After(mentions[j].CreatedAt)
	})

	// Get geo info from the first record we find or resolver
	var countryCode, countryName, asn, asName, netblock string
	var cache db.GeoCache
	if err := db.DB.Where("ip = ?", ip).First(&cache).Error; err == nil {
		countryCode = cache.CountryCode
		countryName = cache.CountryName
		asn = cache.ASN
		asName = cache.ASName
		netblock = cache.Netblock
	}
	if countryCode == "" || countryCode == "UN" || countryCode == "??" {
		var firstAttempt db.Attempt
		if err := db.DB.Where("remote_ip = ? AND country_code != '' AND country_code != 'UN' AND country_code != '??'", ip).First(&firstAttempt).Error; err == nil {
			countryCode = firstAttempt.CountryCode
			countryName = firstAttempt.CountryName
			asn = firstAttempt.ASN
			asName = firstAttempt.ASName
			netblock = firstAttempt.Netblock
		}
	}
	if (countryCode == "" || countryCode == "UN" || countryCode == "??") && ws.geo != nil {
		countryCode, countryName, asn, asName, netblock = ws.geo.Resolve(ip)
	}

	asnType := db.ClassifyASNCompanyType(asName, asn)

	respObj := map[string]interface{}{
		"ip":                        ip,
		"attempts_count":            attemptsCount,
		"credentials":               creds,
		"commands":                  commands,
		"recent_attempts":           allAttempts,
		"attempts":                  allAttempts,
		"web_requests":              webReqs,
		"secondary_attack_mentions": mentions,
		"country_code":              countryCode,
		"country_name":              countryName,
		"asn":                       asn,
		"as_name":                   asName,
		"asn_type":                  asnType,
		"netblock":                  netblock,
	}

	return json.Marshal(respObj)
}

func (ws *WebServer) handleScans(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	sensor := sanitizeInput(r.URL.Query().Get("sensor"))
	q := sanitizeInput(r.URL.Query().Get("q"))
	if q == "" {
		q = sanitizeInput(r.URL.Query().Get("search"))
	}
	ipFilter := sanitizeInput(r.URL.Query().Get("ip"))
	if ipFilter == "" {
		ipFilter = sanitizeInput(r.URL.Query().Get("host"))
	}
	pathFilter := sanitizeInput(r.URL.Query().Get("path"))
	pageStr := r.URL.Query().Get("page")
	limitStr := r.URL.Query().Get("limit")
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))

	query := db.DB.Model(&db.Attempt{}).Where("protocol = ?", "web")
	query = db.ApplySensorFilter(query, sensor)

	if q != "" {
		qLower := "%" + strings.ToLower(q) + "%"
		query = query.Where("LOWER(remote_ip) LIKE ? OR LOWER(raw_data) LIKE ?", qLower, qLower)
	}
	if ipFilter != "" {
		query = query.Where("remote_ip LIKE ? OR sensor_id LIKE ?", "%"+ipFilter+"%", "%"+ipFilter+"%")
	}
	if pathFilter != "" {
		query = query.Where("raw_data LIKE ?", "%"+pathFilter+"%")
	}

	if format == "csv" {
		var attempts []db.Attempt
		if err := query.Order("created_at desc").Find(&attempts).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		tsStr := time.Now().Format("20060102_150405")
		filename := fmt.Sprintf("honeygo_web_scans_%s.csv", tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"Timestamp", "Sensor", "Remote IP", "Method & Path", "User-Agent"})
		for _, a := range attempts {
			methodPath, userAgent, _ := parseRawHTTP(a.RawData)
			sensorID := a.SensorID
			if sensorID == "" {
				sensorID = "local"
			}
			_ = cw.Write([]string{
				a.CreatedAt.Format("2006-01-02 15:04:05"),
				sanitizeCSVField(sensorID),
				sanitizeCSVField(a.RemoteIP),
				sanitizeCSVField(methodPath),
				sanitizeCSVField(userAgent),
			})
		}
		cw.Flush()
		return
	}

	type ScanResp struct {
		ID            uint      `json:"id"`
		CreatedAt     time.Time `json:"created_at"`
		SensorID      string    `json:"sensor_id"`
		RemoteIP      string    `json:"remote_ip"`
		Port          int       `json:"port"`
		MethodPath    string    `json:"method_path"`
		UserAgent     string    `json:"user_agent"`
		CustomHeaders string    `json:"custom_headers"`
		RawHex        string    `json:"raw_hex,omitempty"`
		RawBase64     string    `json:"raw_base64,omitempty"`
		SizeBytes     int       `json:"size_bytes"`
	}

	w.Header().Set("Content-Type", "application/json")

	isPaginated := pageStr != "" || r.URL.Query().Get("paginated") == "true"
	if isPaginated {
		page := 1
		if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
			page = p
		}
		limit := 25
		if limitStr == "all" {
			limit = 0
		} else if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}

		var totalCount int64
		query.Count(&totalCount)

		var attempts []db.Attempt
		pagedQuery := query.Select("id, created_at, sensor_id, remote_ip, port, raw_data").Order("created_at desc")
		if limit > 0 {
			offset := (page - 1) * limit
			pagedQuery = pagedQuery.Offset(offset).Limit(limit)
		}
		if err := pagedQuery.Find(&attempts).Error; err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		resps := make([]ScanResp, 0, len(attempts))
		for _, a := range attempts {
			methodPath, userAgent, customHeaders := parseRawHTTP(a.RawData)
			sensorID := a.SensorID
			if sensorID == "" {
				sensorID = "local"
			}
			resps = append(resps, ScanResp{
				ID:            a.ID,
				CreatedAt:     a.CreatedAt,
				SensorID:      sensorID,
				RemoteIP:      a.RemoteIP,
				Port:          a.Port,
				MethodPath:    methodPath,
				UserAgent:     userAgent,
				CustomHeaders: customHeaders,
				SizeBytes:     len(a.RawData),
			})
		}

		totalPages := 1
		if limit > 0 && totalCount > 0 {
			totalPages = int((totalCount + int64(limit) - 1) / int64(limit))
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"total":       totalCount,
			"page":        page,
			"page_size":   limit,
			"total_pages": totalPages,
			"scans":       resps,
		})
		return
	}

	// Non-paginated path (for backward compatibility with tests like TestHandleScans_NoHardLimit)
	limit := 0
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if limit > 0 {
		query = query.Limit(limit)
	}

	var attempts []db.Attempt
	if err := query.Order("created_at desc").Find(&attempts).Error; err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resps := make([]ScanResp, 0, len(attempts))
	for _, a := range attempts {
		methodPath, userAgent, customHeaders := parseRawHTTP(a.RawData)
		sensorID := a.SensorID
		if sensorID == "" {
			sensorID = "local"
		}
		resps = append(resps, ScanResp{
			ID:            a.ID,
			CreatedAt:     a.CreatedAt,
			SensorID:      sensorID,
			RemoteIP:      a.RemoteIP,
			Port:          a.Port,
			MethodPath:    methodPath,
			UserAgent:     userAgent,
			CustomHeaders: customHeaders,
			SizeBytes:     len(a.RawData),
		})
	}

	json.NewEncoder(w).Encode(resps)
}

func (ws *WebServer) handleRequestDetail(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		idStr = strings.TrimPrefix(r.URL.Path, "/api/requests/detail/")
		idStr = strings.TrimSuffix(idStr, "/")
	}
	id64, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil || id64 == 0 {
		http.Error(w, "Valid request ID required", http.StatusBadRequest)
		return
	}

	attempt, err := db.GetAttemptByID(uint(id64))
	if err != nil {
		http.Error(w, "Request not found: "+err.Error(), http.StatusNotFound)
		return
	}

	rawBytes := []byte(attempt.RawData)
	methodPath, userAgent, customHeaders := parseRawHTTP(attempt.RawData)
	sensorID := attempt.SensorID
	if sensorID == "" {
		sensorID = "local"
	}

	resp := map[string]interface{}{
		"id":             attempt.ID,
		"created_at":     attempt.CreatedAt,
		"sensor_id":      sensorID,
		"protocol":       attempt.Protocol,
		"remote_ip":      attempt.RemoteIP,
		"port":           attempt.Port,
		"country_code":   attempt.CountryCode,
		"country_name":   attempt.CountryName,
		"asn":            attempt.ASN,
		"as_name":        attempt.ASName,
		"netblock":       attempt.Netblock,
		"method_path":    methodPath,
		"user_agent":     userAgent,
		"custom_headers": customHeaders,
		"raw_data":       attempt.RawData,
		"raw_hex":        db.FormatRawHex(rawBytes),
		"hexdump":        db.FormatHexDump(rawBytes),
		"ascii_escaped":  db.FormatASCII(rawBytes),
		"raw_base64":     db.FormatBase64(rawBytes),
		"size_bytes":     len(rawBytes),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (ws *WebServer) handleDownloadRequest(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	id64, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil || id64 == 0 {
		http.Error(w, "Valid request ID required", http.StatusBadRequest)
		return
	}

	attempt, err := db.GetAttemptByID(uint(id64))
	if err != nil {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "" {
		format = "raw"
	}

	rawBytes := []byte(attempt.RawData)
	tsStr := attempt.CreatedAt.Format("20060102_150405")
	cleanIP := strings.ReplaceAll(attempt.RemoteIP, ":", "_")

	switch format {
	case "raw", "bin", "req":
		filename := fmt.Sprintf("honeygo_req_%d_%s_%s.bin", attempt.ID, cleanIP, tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(rawBytes)

	case "hex":
		subType := strings.ToLower(r.URL.Query().Get("type"))
		var out []byte
		var filename string
		if subType == "raw" || subType == "string" {
			filename = fmt.Sprintf("honeygo_req_%d_%s_%s_raw.hex", attempt.ID, cleanIP, tsStr)
			out = []byte(db.FormatRawHex(rawBytes))
		} else {
			filename = fmt.Sprintf("honeygo_req_%d_%s_%s_hexdump.hex", attempt.ID, cleanIP, tsStr)
			out = []byte(db.FormatHexDump(rawBytes))
		}
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write(out)

	case "ascii", "txt":
		filename := fmt.Sprintf("honeygo_req_%d_%s_%s_ascii.txt", attempt.ID, cleanIP, tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(db.FormatASCII(rawBytes)))

	case "base64", "b64":
		filename := fmt.Sprintf("honeygo_req_%d_%s_%s.b64", attempt.ID, cleanIP, tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(db.FormatBase64(rawBytes)))

	default:
		http.Error(w, "Unsupported format. Supported formats: raw, hex, ascii, base64", http.StatusBadRequest)
	}
}

func parseRawHTTP(rawData string) (methodPath string, userAgent string, customHeaders string) {
	normalized := strings.ReplaceAll(rawData, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")
	if len(lines) == 0 || lines[0] == "" {
		return "UNKNOWN", "Unknown", "-"
	}

	// First line: e.g., "GET /.env HTTP/1.1"
	firstLine := strings.TrimSpace(lines[0])
	words := strings.Split(firstLine, " ")
	if len(words) >= 2 {
		methodPath = words[0] + " " + words[1]
	} else {
		methodPath = firstLine
	}

	userAgent = "Unknown"
	var custom []string

	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			name := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])

			lowerName := strings.ToLower(name)
			if lowerName == "user-agent" {
				userAgent = val
			} else if lowerName != "host" && lowerName != "connection" && lowerName != "accept" && lowerName != "content-length" && lowerName != "content-type" && lowerName != "authorization" {
				custom = append(custom, name+": "+val)
			}
		}
	}

	if len(custom) > 0 {
		customHeaders = strings.Join(custom, " | ")
	} else {
		customHeaders = "-"
	}

	return methodPath, userAgent, customHeaders
}

func (ws *WebServer) handleExportLogs(w http.ResponseWriter, r *http.Request) {
	service := sanitizeInput(r.URL.Query().Get("service"))
	sensor := sanitizeInput(r.URL.Query().Get("sensor"))
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if service == "" {
		service = "all"
	}
	if format == "" {
		format = "text"
	}

	var attempts []db.Attempt
	var err error
	query := db.DB.Model(&db.Attempt{})
	if service != "all" {
		query = query.Where("protocol = ?", service)
	}
	if sensor != "" && sensor != "all" {
		query = query.Where("sensor_id = ?", sensor)
	}

	err = query.Order("created_at asc").Find(&attempts).Error
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	tsStr := time.Now().Format("20060102_150405")
	sensorTag := ""
	if sensor != "" && sensor != "all" {
		sensorTag = "_" + sensor
	}

	switch format {
	case "raw", "bin":
		var sb strings.Builder
		for _, a := range attempts {
			sb.WriteString(fmt.Sprintf("### ATTEMPT_ID: %d | PROTOCOL: %s | SENSOR: %s | REMOTE_IP: %s | PORT: %d | TIME: %s ###\n",
				a.ID, a.Protocol, a.SensorID, a.RemoteIP, a.Port, a.CreatedAt.UTC().Format(time.RFC3339)))
			sb.WriteString(a.RawData)
			sb.WriteString("\n\n")
		}
		filename := fmt.Sprintf("honeygo_logs_%s%s_%s.raw", service, sensorTag, tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte(sb.String()))

	case "hex":
		var sb strings.Builder
		for _, a := range attempts {
			rawBytes := []byte(a.RawData)
			sb.WriteString(fmt.Sprintf("================================================================================\n"))
			sb.WriteString(fmt.Sprintf("Attempt ID:   %d\n", a.ID))
			sb.WriteString(fmt.Sprintf("Timestamp:    %s\n", a.CreatedAt.Local().Format("2006-01-02 15:04:05 MST")))
			sb.WriteString(fmt.Sprintf("Protocol:     %s\n", a.Protocol))
			sb.WriteString(fmt.Sprintf("Sensor:       %s\n", a.SensorID))
			sb.WriteString(fmt.Sprintf("Remote IP:    %s:%d\n", a.RemoteIP, a.Port))
			sb.WriteString(fmt.Sprintf("Raw Hex:      %s\n", db.FormatRawHex(rawBytes)))
			sb.WriteString(fmt.Sprintf("Payload Size: %d bytes\n", len(rawBytes)))
			sb.WriteString(fmt.Sprintf("--- HEX DUMP ---\n"))
			sb.WriteString(db.FormatHexDump(rawBytes))
			sb.WriteString(fmt.Sprintf("================================================================================\n\n"))
		}
		filename := fmt.Sprintf("honeygo_logs_%s%s_%s_hexdump.hex", service, sensorTag, tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(sb.String()))

	case "ascii":
		var sb strings.Builder
		for _, a := range attempts {
			rawBytes := []byte(a.RawData)
			sb.WriteString(fmt.Sprintf("================================================================================\n"))
			sb.WriteString(fmt.Sprintf("Attempt ID:   %d\n", a.ID))
			sb.WriteString(fmt.Sprintf("Timestamp:    %s\n", a.CreatedAt.Local().Format("2006-01-02 15:04:05 MST")))
			sb.WriteString(fmt.Sprintf("Protocol:     %s\n", a.Protocol))
			sb.WriteString(fmt.Sprintf("Sensor:       %s\n", a.SensorID))
			sb.WriteString(fmt.Sprintf("Remote IP:    %s:%d\n", a.RemoteIP, a.Port))
			sb.WriteString(fmt.Sprintf("Payload Size: %d bytes\n", len(rawBytes)))
			sb.WriteString(fmt.Sprintf("--- ASCII ESCAPED ---\n"))
			sb.WriteString(db.FormatASCII(rawBytes))
			sb.WriteString(fmt.Sprintf("\n================================================================================\n\n"))
		}
		filename := fmt.Sprintf("honeygo_logs_%s%s_%s_ascii.txt", service, sensorTag, tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(sb.String()))

	case "base64", "b64":
		var sb strings.Builder
		for _, a := range attempts {
			rawBytes := []byte(a.RawData)
			sb.WriteString(fmt.Sprintf("### ATTEMPT_ID: %d | PROTOCOL: %s | SENSOR: %s | REMOTE_IP: %s | PORT: %d | BASE64 ###\n",
				a.ID, a.Protocol, a.SensorID, a.RemoteIP, a.Port))
			sb.WriteString(db.FormatBase64(rawBytes))
			sb.WriteString("\n\n")
		}
		filename := fmt.Sprintf("honeygo_logs_%s%s_%s.b64", service, sensorTag, tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(sb.String()))

	case "json":
		type JSONExportItem struct {
			ID           uint      `json:"id"`
			CreatedAt    time.Time `json:"created_at"`
			SensorID     string    `json:"sensor_id"`
			Protocol     string    `json:"protocol"`
			RemoteIP     string    `json:"remote_ip"`
			Port         int       `json:"port"`
			CountryCode  string    `json:"country_code"`
			CountryName  string    `json:"country_name"`
			ASN          string    `json:"asn"`
			ASName       string    `json:"as_name"`
			MethodPath   string    `json:"method_path,omitempty"`
			UserAgent    string    `json:"user_agent,omitempty"`
			RawHex       string    `json:"raw_hex"`
			RawBase64    string    `json:"raw_base64"`
			ASCIIEscaped string    `json:"ascii_escaped"`
			HexDump      string    `json:"hexdump"`
			SizeBytes    int       `json:"size_bytes"`
		}
		items := make([]JSONExportItem, 0, len(attempts))
		for _, a := range attempts {
			rawBytes := []byte(a.RawData)
			var mp, ua string
			if strings.EqualFold(a.Protocol, "web") {
				mp, ua, _ = parseRawHTTP(a.RawData)
			}
			items = append(items, JSONExportItem{
				ID:           a.ID,
				CreatedAt:    a.CreatedAt,
				SensorID:     a.SensorID,
				Protocol:     a.Protocol,
				RemoteIP:     a.RemoteIP,
				Port:         a.Port,
				CountryCode:  a.CountryCode,
				CountryName:  a.CountryName,
				ASN:          a.ASN,
				ASName:       a.ASName,
				MethodPath:   mp,
				UserAgent:    ua,
				RawHex:       db.FormatRawHex(rawBytes),
				RawBase64:    db.FormatBase64(rawBytes),
				ASCIIEscaped: db.FormatASCII(rawBytes),
				HexDump:      db.FormatHexDump(rawBytes),
				SizeBytes:    len(rawBytes),
			})
		}
		filename := fmt.Sprintf("honeygo_logs_%s%s_%s.json", service, sensorTag, tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(items)

	case "csv":
		tsStr := time.Now().Format("20060102_150405")
		filename := fmt.Sprintf("honeygo_logs_%s%s_%s.csv", service, sensorTag, tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"Timestamp", "Sensor", "Protocol", "Country Code", "Country Name", "ASN", "AS Name", "Remote IP", "Port", "Method and Path", "User Agent", "Payload Size (Bytes)"})
		for _, a := range attempts {
			var mp, ua string
			if strings.EqualFold(a.Protocol, "web") {
				mp, ua, _ = parseRawHTTP(a.RawData)
			}
			_ = cw.Write([]string{
				a.CreatedAt.UTC().Format(time.RFC3339),
				sanitizeCSVField(a.SensorID),
				sanitizeCSVField(a.Protocol),
				sanitizeCSVField(a.CountryCode),
				sanitizeCSVField(a.CountryName),
				sanitizeCSVField(a.ASN),
				sanitizeCSVField(a.ASName),
				sanitizeCSVField(a.RemoteIP),
				strconv.Itoa(a.Port),
				sanitizeCSVField(mp),
				sanitizeCSVField(ua),
				strconv.Itoa(len(a.RawData)),
			})
		}
		cw.Flush()

	default: // "text"
		var sb strings.Builder
		for _, a := range attempts {
			sb.WriteString(fmt.Sprintf("=========================================\n"))
			sb.WriteString(fmt.Sprintf("Timestamp: %s\n", a.CreatedAt.Local().Format("2006-01-02 15:04:05 MST")))
			sb.WriteString(fmt.Sprintf("Sensor:    %s\n", a.SensorID))
			sb.WriteString(fmt.Sprintf("Protocol:  %s\n", a.Protocol))
			sb.WriteString(fmt.Sprintf("Remote IP: %s\n", a.RemoteIP))
			sb.WriteString(fmt.Sprintf("Port:      %d\n", a.Port))
			sb.WriteString(fmt.Sprintf("Raw Request:\n%s\n", a.RawData))
			sb.WriteString(fmt.Sprintf("=========================================\n\n"))
		}
		filename := fmt.Sprintf("honeygo_logs_%s%s_%s.txt", service, sensorTag, tsStr)
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(sb.String()))
	}
}

func (ws *WebServer) handleCountryDetails(w http.ResponseWriter, r *http.Request) {
	rawCountryCode := strings.TrimPrefix(r.URL.Path, "/api/country/")
	countryCode := sanitizeInput(rawCountryCode)
	if countryCode == "" {
		http.Error(w, "Country code required", http.StatusBadRequest)
		return
	}
	sensor := sanitizeInput(r.URL.Query().Get("sensor"))

	cacheKey := fmt.Sprintf("country:%s:%s", countryCode, sensor)
	if data, ok := getCachedAPI(cacheKey, 30*time.Second); ok {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	var countryName string
	db.DB.Model(&db.Attempt{}).
		Where("country_code = ?", countryCode).
		Select("country_name").
		Limit(1).
		Row().
		Scan(&countryName)

	if countryName == "" {
		db.DB.Model(&db.Credential{}).
			Where("country_code = ?", countryCode).
			Select("country_name").
			Limit(1).
			Row().
			Scan(&countryName)
	}

	if countryName == "" {
		countryName = "Unknown Country"
	}

	var totalAttempts int64
	attemptsCountQuery := db.DB.Model(&db.Attempt{}).Where("country_code = ?", countryCode)
	if sensor != "" && sensor != "all" {
		attemptsCountQuery = attemptsCountQuery.Where("sensor_id = ?", sensor)
	}
	attemptsCountQuery.Count(&totalAttempts)

	type ProtoCount struct {
		Protocol string `json:"protocol"`
		Count    int64  `json:"count"`
	}
	var protoCounts []ProtoCount
	protoQuery := db.DB.Model(&db.Attempt{}).
		Select("protocol, count(*) as count").
		Where("country_code = ?", countryCode)
	if sensor != "" && sensor != "all" {
		protoQuery = protoQuery.Where("sensor_id = ?", sensor)
	}
	protoQuery.Group("protocol").Order("count desc, protocol asc").Scan(&protoCounts)

	var attempts []db.Attempt
	attemptsListQuery := db.DB.Model(&db.Attempt{}).Where("country_code = ?", countryCode)
	attemptsListQuery = db.ApplySensorFilter(attemptsListQuery, sensor)
	attemptsListQuery.Order("created_at desc").Limit(200).Find(&attempts)

	type CountryAttempt struct {
		CreatedAt time.Time `json:"created_at"`
		SensorID  string    `json:"sensor_id"`
		RemoteIP  string    `json:"remote_ip"`
		Protocol  string    `json:"protocol"`
		Port      int       `json:"port"`
		ExtraInfo string    `json:"extra_info"`
	}

	// Pre-fetch matching credentials in bulk to avoid N+1 query loop
	var creds []db.Credential
	if len(attempts) > 0 {
		var ips []string
		for _, a := range attempts {
			if a.Protocol != "web" {
				ips = append(ips, a.RemoteIP)
			}
		}
		if len(ips) > 0 {
			db.DB.Where("remote_ip IN (?)", ips).Order("created_at desc").Limit(200).Find(&creds)
		}
	}
	credMap := make(map[string]string)
	for _, c := range creds {
		key := fmt.Sprintf("%s_%s", c.RemoteIP, strings.ToLower(c.Protocol))
		if _, exists := credMap[key]; !exists {
			credMap[key] = fmt.Sprintf("Captured Creds: %s / %s", c.Username, c.Password)
		}
	}

	resps := make([]CountryAttempt, 0, len(attempts))
	for _, a := range attempts {
		extra := "-"
		if a.Protocol == "web" {
			methodPath, _, _ := parseRawHTTP(a.RawData)
			extra = methodPath
		} else {
			key := fmt.Sprintf("%s_%s", a.RemoteIP, strings.ToLower(a.Protocol))
			if info, ok := credMap[key]; ok {
				extra = info
			}
		}
		resps = append(resps, CountryAttempt{
			CreatedAt: a.CreatedAt,
			SensorID:  a.SensorID,
			RemoteIP:  a.RemoteIP,
			Protocol:  a.Protocol,
			Port:      a.Port,
			ExtraInfo: extra,
		})
	}

	respObj := map[string]interface{}{
		"country_code": countryCode,
		"country_name": countryName,
		"total":        totalAttempts,
		"protocols":    protoCounts,
		"attempts":     resps,
	}

	if data, err := json.Marshal(respObj); err == nil {
		setCachedAPI(cacheKey, data)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respObj)
}

func (ws *WebServer) handleCommands(w http.ResponseWriter, r *http.Request) {
	sensor := sanitizeInput(r.URL.Query().Get("sensor"))
	q := sanitizeInput(r.URL.Query().Get("q"))
	if q == "" {
		q = sanitizeInput(r.URL.Query().Get("search"))
	}
	limitStr := r.URL.Query().Get("limit")
	limit := 0 // 0 means return all executed commands without arbitrary cutoff
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	cacheKey := fmt.Sprintf("commands:%s:%s:%d", sensor, q, limit)
	if data, ok := getCachedAPI(cacheKey, 10*time.Second); ok {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	var recent []db.Command
	cmdQuery := db.DB.Model(&db.Command{}).Order("created_at desc")
	cmdQuery = db.ApplySensorFilter(cmdQuery, sensor)
	if q != "" {
		qLower := "%" + strings.ToLower(q) + "%"
		cmdQuery = cmdQuery.Where("LOWER(command) LIKE ? OR LOWER(remote_ip) LIKE ? OR LOWER(username) LIKE ? OR LOWER(protocol) LIKE ? OR LOWER(country_name) LIKE ? OR LOWER(country_code) LIKE ? OR LOWER(asn) LIKE ? OR LOWER(as_name) LIKE ?", qLower, qLower, qLower, qLower, qLower, qLower, qLower, qLower)
	}
	if limit > 0 {
		cmdQuery = cmdQuery.Limit(limit)
	}
	cmdQuery.Find(&recent)

	popular, _ := db.GetTopCommandsFilter(50, sensor)

	respObj := map[string]interface{}{
		"recent":  recent,
		"popular": popular,
	}

	if data, err := json.Marshal(respObj); err == nil {
		setCachedAPI(cacheKey, data)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(respObj)
}

func (ws *WebServer) handleCorrelations(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")

	sensor := r.URL.Query().Get("sensor")
	if data, ok := db.GetCachedCorrelationJSON(sensor); ok {
		w.Write(data)
		return
	}

	report, err := db.GetCorrelationReportFilter(sensor, 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if data, err := json.Marshal(report); err == nil {
		db.SetCachedCorrelationJSON(sensor, data, report)
		w.Write(data)
		return
	}
	json.NewEncoder(w).Encode(report)
}

func (ws *WebServer) handleICS(w http.ResponseWriter, r *http.Request) {
	sensor := r.URL.Query().Get("sensor")
	cacheKey := "ics:" + sensor
	if data, ok := getCachedAPI(cacheKey, 15*time.Second); ok {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	report, err := db.GetICSReportFilter(sensor)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if data, err := json.Marshal(report); err == nil {
		setCachedAPI(cacheKey, data)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(report)
}

func (ws *WebServer) handleSystemLogs(w http.ResponseWriter, r *http.Request) {
	cat := r.URL.Query().Get("category")
	lvl := r.URL.Query().Get("level")
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	cacheKey := fmt.Sprintf("syslogs:%s:%s:%d", cat, lvl, limit)
	if data, ok := getCachedAPI(cacheKey, 5*time.Second); ok {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	entries := syslog.GetEntries(cat, lvl, limit)
	if data, err := json.Marshal(entries); err == nil {
		setCachedAPI(cacheKey, data)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

func (ws *WebServer) handleMISPStatus(w http.ResponseWriter, r *http.Request) {
	cacheKey := "misp:status"
	if data, ok := getCachedAPI(cacheKey, 10*time.Second); ok {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	status := misp.GetStatus()
	if data, err := json.Marshal(status); err == nil {
		setCachedAPI(cacheKey, data)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (ws *WebServer) handleMISPConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		ws.handleMISPStatus(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Enabled    bool   `json:"enabled"`
		URL        string `json:"url"`
		APIKey     string `json:"api_key"`
		SkipVerify bool   `json:"skip_verify"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	existingURL, existingKey, _ := misp.GetConfig()
	apiKey := req.APIKey
	if apiKey == "" || misp.IsMaskedKey(apiKey, existingKey) {
		apiKey = existingKey
	}
	url := req.URL
	if url == "" {
		url = existingURL
	}

	if !req.Enabled {
		misp.Init(url, apiKey, req.SkipVerify, nil)
		misp.Disable()
		syslog.Info(syslog.CategoryMISP, "MISP threat sharing integration disabled via WebUI (Settings preserved for: %s)", url)
	} else {
		if url == "" {
			http.Error(w, "MISP Server URL cannot be empty when enabled", http.StatusBadRequest)
			return
		}
		if apiKey == "" {
			http.Error(w, "MISP API Auth Key cannot be empty when enabled", http.StatusBadRequest)
			return
		}
		misp.Init(url, apiKey, req.SkipVerify, nil)
		syslog.Info(syslog.CategoryMISP, "MISP threat sharing integration enabled for server: %s (Skip SSL: %t)", url, req.SkipVerify)
	}

	status := misp.GetStatus()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (ws *WebServer) handleMISPTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL        string `json:"url"`
		APIKey     string `json:"api_key"`
		SkipVerify bool   `json:"skip_verify"`
	}

	_ = json.NewDecoder(r.Body).Decode(&req)
	url := req.URL
	apiKey := req.APIKey
	skipVerify := req.SkipVerify

	cfgURL, cfgKey, cfgSkip := misp.GetConfig()
	if url == "" {
		url = cfgURL
	}
	if apiKey == "" || misp.IsMaskedKey(apiKey, cfgKey) {
		apiKey = cfgKey
	}
	if !req.SkipVerify && url == cfgURL {
		skipVerify = cfgSkip
	}

	if url == "" || apiKey == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(misp.TestResult{
			Success: false,
			Error:   "MISP Server URL and API Key are required to test connectivity.",
		})
		return
	}

	res, _ := misp.TestConnection(url, apiKey, skipVerify)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func (ws *WebServer) handleMISPCanary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		URL        string `json:"url"`
		APIKey     string `json:"api_key"`
		SkipVerify bool   `json:"skip_verify"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.URL != "" {
		_, existingKey, _ := misp.GetConfig()
		apiKey := req.APIKey
		if apiKey == "" || misp.IsMaskedKey(apiKey, existingKey) {
			apiKey = existingKey
		}
		if apiKey != "" {
			misp.Init(req.URL, apiKey, req.SkipVerify, nil)
		}
	}

	res, err := misp.PushCanaryTestEvent()
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   res.Error,
		})
		return
	}
	json.NewEncoder(w).Encode(res)
}

func (ws *WebServer) handleMISPEvents(w http.ResponseWriter, r *http.Request) {
	cacheKey := "misp:events"
	if data, ok := getCachedAPI(cacheKey, 15*time.Second); ok {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	status := misp.GetStatus()
	if data, err := json.Marshal(status.RecentEvents); err == nil {
		setCachedAPI(cacheKey, data)
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
		return
	}

	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status.RecentEvents)
}

func (ws *WebServer) handleReconList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	filter := r.URL.Query().Get("filter")
	limitStr := r.URL.Query().Get("limit")
	limit := 0
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
		limit = l
	}

	cacheKey := fmt.Sprintf("recon:%s:%d", filter, limit)
	if data, ok := getCachedAPI(cacheKey, 15*time.Second); ok {
		w.Write(data)
		return
	}

	targets, err := db.GetReconTargets(filter, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	total, droppers, canaryHits, highRisk := db.GetReconStats()

	respObj := map[string]interface{}{
		"auto_recon": recon.IsAutoReconEnabled(),
		"stats": map[string]interface{}{
			"total":       total,
			"c2_droppers": droppers,
			"canary_hits": canaryHits,
			"high_risk":   highRisk,
		},
		"targets": targets,
	}

	if data, err := json.Marshal(respObj); err == nil {
		setCachedAPI(cacheKey, data)
		w.Write(data)
		return
	}

	json.NewEncoder(w).Encode(respObj)
}

func (ws *WebServer) handleReconTarget(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, "missing ip parameter", http.StatusBadRequest)
		return
	}

	target, err := db.GetReconTarget(ip)
	if err != nil {
		http.Error(w, "target not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"target": target,
	})
}

func (ws *WebServer) handleReconScan(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP  string `json:"ip"`
		All bool   `json:"all"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if req.All {
		count := recon.ScanAllPending()
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Queued %d pending targets for PTR and GeoIP enrichment", count),
			"queued":  count,
		})
		return
	}

	if req.IP == "" {
		http.Error(w, "missing ip field", http.StatusBadRequest)
		return
	}

	result, err := recon.ScanTarget(req.IP)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"result":  result,
	})
}

func (ws *WebServer) handleReconConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AutoRecon *bool `json:"auto_recon"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AutoRecon == nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	recon.SetAutoRecon(*req.AutoRecon)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"auto_recon": *req.AutoRecon,
	})
}

func (ws *WebServer) handleReconAddCanary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP      string `json:"ip"`
		Token   string `json:"token"`
		Context string `json:"context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, "missing required 'ip' field", http.StatusBadRequest)
		return
	}

	ctx := req.Context
	if ctx == "" {
		ctx = req.Token
	}
	if ctx == "" {
		ctx = "Manual Canary Token Hit"
	}

	target, err := recon.AddManualCanaryHit(req.IP, ctx)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Canary token hit logged for %s", req.IP),
		"target":  target,
	})
}

func (ws *WebServer) handleReconAddTarget(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		IP         string `json:"ip"`
		SourceType string `json:"source_type"`
		Context    string `json:"context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
		http.Error(w, "missing required 'ip' field", http.StatusBadRequest)
		return
	}

	target, err := recon.AddManualTarget(req.IP, req.SourceType, req.Context)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Target %s registered successfully", req.IP),
		"target":  target,
	})
}
