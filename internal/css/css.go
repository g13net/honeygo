package css

import (
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"honeygo/internal/db"
	"honeygo/internal/syslog"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ServiceInfo struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Status   string `json:"status"`
	Isolated bool   `json:"isolated"`
}

type SensorCommand struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"` // "start" or "stop"
	Protocol  string    `json:"protocol"`
	Port      int       `json:"port"`
	Isolated  bool      `json:"isolated"`
	Profile   string    `json:"profile,omitempty"`
	TTL       int       `json:"ttl,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

var (
	cssLogger                      io.Writer
	cssLoggerMu                    sync.RWMutex
	GetRunningServicesFunc         func() []ServiceInfo
	LocalStartServiceFunc          func(protocol string, port int, isolated bool, profile string, ttl int) error
	LocalStopServiceFunc           func(protocol string, port int) error
	LocalIsIsolationEnabledFunc    func() bool
	ExecuteSensorRemoteCommandFunc func(cmd SensorCommand) error

	sensorCommandsMu sync.Mutex
	sensorCommands   = make(map[string][]SensorCommand)
)

func QueueSensorCommand(sensorID string, cmd SensorCommand) {
	sensorCommandsMu.Lock()
	defer sensorCommandsMu.Unlock()
	if cmd.ID == "" {
		cmd.ID = fmt.Sprintf("cmd-%d", time.Now().UnixNano())
	}
	cmd.Timestamp = time.Now()
	sensorCommands[sensorID] = append(sensorCommands[sensorID], cmd)
}

func PopSensorCommands(sensorID string) []SensorCommand {
	sensorCommandsMu.Lock()
	defer sensorCommandsMu.Unlock()
	cmds := sensorCommands[sensorID]
	delete(sensorCommands, sensorID)
	return cmds
}

// SetLogger sets the logger writer for TUI log output
func SetLogger(w io.Writer) {
	cssLoggerMu.Lock()
	defer cssLoggerMu.Unlock()
	cssLogger = w
}

func logCSS(format string, a ...interface{}) {
	if !syslog.IsInfoLoggingEnabled() {
		return
	}
	cssLoggerMu.RLock()
	w := cssLogger
	cssLoggerMu.RUnlock()
	if w != nil {
		fmt.Fprintf(w, format+"\n", a...)
	}
}

func logCSSAlways(format string, a ...interface{}) {
	cssLoggerMu.RLock()
	w := cssLogger
	cssLoggerMu.RUnlock()
	if w != nil {
		fmt.Fprintf(w, format+"\n", a...)
	}
}

func extractRemoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

type Config struct {
	ServerEnabled    bool   `json:"server_enabled"`
	ServerPort       int    `json:"server_port"`
	ServerSSL        bool   `json:"server_ssl"`
	ServerCert       string `json:"server_cert,omitempty"`
	ServerKey        string `json:"server_key,omitempty"`
	TokenAuthEnabled bool   `json:"token_auth_enabled"`
	AuthToken        string `json:"auth_token"`
	IsSensorMode     bool   `json:"is_sensor_mode"`
	CSSURL           string `json:"css_url"`
	CSSSkipVerify    bool   `json:"css_skip_verify"`
	SensorToken      string `json:"sensor_token"`
	SensorID         string `json:"sensor_id"`
	SensorCheckinTTL int    `json:"sensor_checkin_ttl"`
	CartoAPIKey      string `json:"carto_api_key"`
}

var (
	configMu     sync.RWMutex
	globalConfig = &Config{
		ServerPort:       8090,
		ServerSSL:        false,
		SensorID:         getDefaultSensorID(),
		SensorCheckinTTL: 15,
	}
)

// SetSensorSkipVerify configures whether the sensor ignores SSL certificate verification (e.g., self-signed certs)
func SetSensorSkipVerify(skip bool) {
	configMu.Lock()
	defer configMu.Unlock()
	globalConfig.CSSSkipVerify = skip
	updateSensorHTTPClient(skip)
}

// GetSensorSkipVerify returns whether self-signed/unverified SSL certificates are ignored by this sensor
func GetSensorSkipVerify() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return globalConfig.CSSSkipVerify
}

// SetCartoAPIKey sets the CARTO Basemaps API key for threat heatmap visualization
func SetCartoAPIKey(key string) {
	trimmed := strings.TrimSpace(key)
	configMu.Lock()
	globalConfig.CartoAPIKey = trimmed
	configMu.Unlock()
	_ = db.SetSystemSetting("carto_api_key", trimmed)
}

// GetCartoAPIKey returns the active CARTO Basemaps API key
func GetCartoAPIKey() string {
	configMu.RLock()
	key := globalConfig.CartoAPIKey
	configMu.RUnlock()
	if key == "" {
		if val, ok := db.GetSystemSetting("carto_api_key"); ok && val != "" {
			key = val
			configMu.Lock()
			globalConfig.CartoAPIKey = val
			configMu.Unlock()
		}
	}
	return key
}

func getSensorHTTPClient(skipVerify bool) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 50,
			IdleConnTimeout:     90 * time.Second,
			DisableKeepAlives:   false,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
			},
		},
		Timeout: 10 * time.Second,
	}
}

func updateSensorHTTPClient(skipVerify bool) {
	sensorHTTPClient = getSensorHTTPClient(skipVerify)
}

// EventPayload represents a unified event sent from a sensor to CSS
type EventPayload struct {
	EventType   string        `json:"event_type"` // "attempt", "credential", "command", "registration"
	SensorID    string        `json:"sensor_id"`
	Attempt    *db.Attempt    `json:"attempt,omitempty"`
	Credential *db.Credential `json:"credential,omitempty"`
	Command    *db.Command    `json:"command,omitempty"`
}

// BatchEventPayload represents an array of events dispatched together
type BatchEventPayload struct {
	SensorID string         `json:"sensor_id"`
	Events   []EventPayload `json:"events"`
}

var (
	eventIngestChan = make(chan EventPayload, 50000)
	ingestOnce      sync.Once

	sensorHTTPClient = getSensorHTTPClient(false)

	sensorForwardQueue = make(chan EventPayload, 20000)
	sensorBatchOnce    sync.Once
)

func init() {
	startIngestWorker()
	db.IsSensorModeFunc = IsSensorMode
	db.GetSensorIDFunc = GetSensorID
	db.ForwardEventFunc = func(eventType string, data interface{}) error {
		switch v := data.(type) {
		case *db.Attempt:
			return EnqueueSensorEvent(EventPayload{EventType: eventType, SensorID: v.SensorID, Attempt: v})
		case *db.Credential:
			return EnqueueSensorEvent(EventPayload{EventType: eventType, SensorID: v.SensorID, Credential: v})
		case *db.Command:
			return EnqueueSensorEvent(EventPayload{EventType: eventType, SensorID: v.SensorID, Command: v})
		default:
			return fmt.Errorf("unsupported event data type")
		}
	}
}

func startIngestWorker() {
	ingestOnce.Do(func() {
		go ingestWorkerLoop()
	})
}

func ingestWorkerLoop() {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var attempts []*db.Attempt
	var creds []*db.Credential
	var cmds []*db.Command

	flush := func() {
		if len(attempts) == 0 && len(creds) == 0 && len(cmds) == 0 {
			return
		}
		if db.DB != nil {
			if len(attempts) > 0 {
				_ = db.DB.CreateInBatches(attempts, 100)
			}
			if len(creds) > 0 {
				_ = db.DB.CreateInBatches(creds, 100)
				for _, c := range creds {
					if db.OnCredentialRecorded != nil {
						db.OnCredentialRecorded(c.Protocol, c.RemoteIP, c.Username, c.Password)
					}
				}
			}
			if len(cmds) > 0 {
				_ = db.DB.CreateInBatches(cmds, 100)
				for _, cmd := range cmds {
					if db.OnCommandRecorded != nil {
						db.OnCommandRecorded(cmd.Protocol, cmd.RemoteIP, cmd.Username, cmd.Command)
					}
				}
			}
			db.TriggerThreatIntelUpdate()
		}
		attempts = attempts[:0]
		creds = creds[:0]
		cmds = cmds[:0]
	}

	for {
		select {
		case evt := <-eventIngestChan:
			switch evt.EventType {
			case "attempt":
				if evt.Attempt != nil {
					if evt.Attempt.SensorID == "" {
						evt.Attempt.SensorID = evt.SensorID
					}
					attempts = append(attempts, evt.Attempt)
				}
			case "credential":
				if evt.Credential != nil {
					if evt.Credential.SensorID == "" {
						evt.Credential.SensorID = evt.SensorID
					}
					creds = append(creds, evt.Credential)
				}
			case "command":
				if evt.Command != nil {
					if evt.Command.SensorID == "" {
						evt.Command.SensorID = evt.SensorID
					}
					cmds = append(cmds, evt.Command)
				}
			}

			if len(attempts)+len(creds)+len(cmds) >= 100 {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

func QueueEventForIngest(p EventPayload) {
	select {
	case eventIngestChan <- p:
	default:
		processSingleEventDirect(p)
	}
}

func processSingleEventDirect(payload EventPayload) {
	if db.DB == nil {
		return
	}
	switch payload.EventType {
	case "attempt":
		if payload.Attempt != nil {
			if payload.Attempt.SensorID == "" {
				payload.Attempt.SensorID = payload.SensorID
			}
			_ = db.DB.Create(payload.Attempt)
		}
	case "credential":
		if payload.Credential != nil {
			if payload.Credential.SensorID == "" {
				payload.Credential.SensorID = payload.SensorID
			}
			_ = db.DB.Create(payload.Credential)
			if db.OnCredentialRecorded != nil {
				db.OnCredentialRecorded(payload.Credential.Protocol, payload.Credential.RemoteIP, payload.Credential.Username, payload.Credential.Password)
			}
		}
	case "command":
		if payload.Command != nil {
			if payload.Command.SensorID == "" {
				payload.Command.SensorID = payload.SensorID
			}
			_ = db.DB.Create(payload.Command)
			if db.OnCommandRecorded != nil {
				db.OnCommandRecorded(payload.Command.Protocol, payload.Command.RemoteIP, payload.Command.Username, payload.Command.Command)
			}
		}
	}
	db.TriggerThreatIntelUpdate(payload.SensorID)
}

func startSensorBatchForwarder() {
	sensorBatchOnce.Do(func() {
		go sensorBatchForwarderLoop()
	})
}

func EnqueueSensorEvent(payload EventPayload) error {
	if !IsSensorMode() {
		return nil
	}
	select {
	case sensorForwardQueue <- payload:
		return nil
	default:
		go func() {
			_ = ForwardEventToCSS(payload)
		}()
		return nil
	}
}

func sensorBatchForwarderLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	var batch []EventPayload

	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		toSend := make([]EventPayload, len(batch))
		copy(toSend, batch)
		batch = batch[:0]

		go func(events []EventPayload) {
			_ = ForwardBatchEventsToCSS(events)
		}(toSend)
	}

	for {
		select {
		case evt := <-sensorForwardQueue:
			if !IsSensorMode() {
				continue
			}
			batch = append(batch, evt)
			if len(batch) >= 100 {
				flushBatch()
			}
		case <-ticker.C:
			if IsSensorMode() && len(batch) > 0 {
				flushBatch()
			}
		}
	}
}

func ForwardBatchEventsToCSS(events []EventPayload) error {
	if len(events) == 0 {
		return nil
	}

	configMu.RLock()
	cssURL := globalConfig.CSSURL
	token := globalConfig.SensorToken
	sensorID := globalConfig.SensorID
	configMu.RUnlock()

	if cssURL == "" {
		return fmt.Errorf("CSS URL is not configured")
	}

	for i := range events {
		if events[i].SensorID == "" {
			events[i].SensorID = sensorID
		}
	}

	batchPayload := BatchEventPayload{
		SensorID: sensorID,
		Events:   events,
	}

	bodyBytes, err := json.Marshal(batchPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal batch payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/css/events/batch", cssURL)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create batch request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-API-Token", token)
	}

	resp, err := sensorHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send batch events to CSS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("CSS server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

func getDefaultSensorID() string {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return "sensor-node-1"
	}
	return hostname
}

func GetConfig() Config {
	configMu.RLock()
	cfg := *globalConfig
	configMu.RUnlock()
	if cfg.CartoAPIKey == "" {
		if val, ok := db.GetSystemSetting("carto_api_key"); ok && val != "" {
			cfg.CartoAPIKey = val
			configMu.Lock()
			globalConfig.CartoAPIKey = val
			configMu.Unlock()
		}
	}
	return cfg
}

func GetSensorCheckinTTL() int {
	configMu.RLock()
	defer configMu.RUnlock()
	if globalConfig.SensorCheckinTTL <= 0 {
		return 15
	}
	return globalConfig.SensorCheckinTTL
}

func SetSensorCheckinTTL(ttl int) {
	if ttl <= 0 {
		ttl = 15
	}
	configMu.Lock()
	globalConfig.SensorCheckinTTL = ttl
	isSensor := globalConfig.IsSensorMode
	configMu.Unlock()

	if isSensor {
		heartbeatMu.Lock()
		if heartbeatResetChan != nil {
			select {
			case heartbeatResetChan <- ttl:
			default:
			}
		}
		heartbeatMu.Unlock()
	}
	syslog.Info(syslog.CategoryCSS, "Sensor checkin TTL configured to %ds", ttl)
}

func UpdateConfig(cfg Config) {
	configMu.Lock()
	oldTTL := globalConfig.SensorCheckinTTL
	globalConfig.ServerEnabled = cfg.ServerEnabled
	if cfg.ServerPort > 0 {
		globalConfig.ServerPort = cfg.ServerPort
	}
	globalConfig.ServerSSL = cfg.ServerSSL
	globalConfig.ServerCert = cfg.ServerCert
	globalConfig.ServerKey = cfg.ServerKey
	globalConfig.TokenAuthEnabled = cfg.TokenAuthEnabled
	globalConfig.AuthToken = strings.TrimSpace(cfg.AuthToken)
	globalConfig.IsSensorMode = cfg.IsSensorMode
	globalConfig.CSSURL = strings.TrimSuffix(strings.TrimSpace(cfg.CSSURL), "/")
	globalConfig.CSSSkipVerify = cfg.CSSSkipVerify
	globalConfig.SensorToken = strings.TrimSpace(cfg.SensorToken)
	if cfg.SensorID != "" {
		globalConfig.SensorID = strings.TrimSpace(cfg.SensorID)
	}
	if cfg.SensorCheckinTTL > 0 {
		globalConfig.SensorCheckinTTL = cfg.SensorCheckinTTL
	}
	globalConfig.CartoAPIKey = strings.TrimSpace(cfg.CartoAPIKey)
	isSensor := globalConfig.IsSensorMode
	newTTL := globalConfig.SensorCheckinTTL
	configMu.Unlock()

	_ = db.SetSystemSetting("carto_api_key", strings.TrimSpace(cfg.CartoAPIKey))
	updateSensorHTTPClient(cfg.CSSSkipVerify)

	if isSensor && oldTTL != newTTL {
		heartbeatMu.Lock()
		if heartbeatResetChan != nil {
			select {
			case heartbeatResetChan <- newTTL:
			default:
			}
		}
		heartbeatMu.Unlock()
	}
}

func IsSensorMode() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return globalConfig.IsSensorMode && globalConfig.CSSURL != ""
}

func IsCSSServerRunning() bool {
	configMu.RLock()
	defer configMu.RUnlock()
	return globalConfig.ServerEnabled
}

func GetSensorID() string {
	configMu.RLock()
	defer configMu.RUnlock()
	if globalConfig.SensorID == "" {
		return "local"
	}
	return globalConfig.SensorID
}

func SetSensorMode(enabled bool, cssURL, token, sensorID string) {
	if !enabled {
		DisconnectSensor()
		return
	}
	_ = ConnectSensor(cssURL, token, sensorID)
}

// DisconnectSensor disconnects from CSS server and stops heartbeats
func DisconnectSensor() {
	heartbeatMu.Lock()
	if heartbeatStopChan != nil {
		close(heartbeatStopChan)
		heartbeatStopChan = nil
	}
	heartbeatMu.Unlock()

	configMu.Lock()
	globalConfig.IsSensorMode = false
	globalConfig.CSSURL = ""
	globalConfig.SensorToken = ""
	configMu.Unlock()

	syslog.Info(syslog.CategoryCSS, "Disconnected sensor mode from CSS server")
}

// ConnectSensor connects and registers a sensor with the CSS server, verifying server acknowledgment
func ConnectSensor(cssURL, token, sensorID string, checkinTTLOpts ...int) error {
	skipVerify := GetSensorSkipVerify()
	ttl := GetSensorCheckinTTL()
	if len(checkinTTLOpts) > 0 && checkinTTLOpts[0] > 0 {
		ttl = checkinTTLOpts[0]
	}
	return ConnectSensorWithVerify(cssURL, token, sensorID, ttl, skipVerify)
}

// ConnectSensorWithVerify connects and registers a sensor with the CSS server with explicit SSL verification control
func ConnectSensorWithVerify(cssURL, token, sensorID string, checkinTTL int, skipVerify bool) error {
	cssURL = strings.TrimSuffix(strings.TrimSpace(cssURL), "/")
	if cssURL == "" {
		return fmt.Errorf("CSS URL cannot be empty")
	}
	token = strings.TrimSpace(token)
	sensorID = strings.TrimSpace(sensorID)
	if sensorID == "" {
		sensorID = GetSensorID()
	}

	if checkinTTL <= 0 {
		checkinTTL = GetSensorCheckinTTL()
	}
	SetSensorCheckinTTL(checkinTTL)
	SetSensorSkipVerify(skipVerify)

	var svcs []ServiceInfo
	if GetRunningServicesFunc != nil {
		svcs = GetRunningServicesFunc()
	}

	isoEnabled := false
	if LocalIsIsolationEnabledFunc != nil {
		isoEnabled = LocalIsIsolationEnabledFunc()
	}

	sensorStatus := "Active"
	if len(svcs) == 0 {
		sensorStatus = "Idle"
	}

	payload := map[string]interface{}{
		"sensor_id":         sensorID,
		"status":            sensorStatus,
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
		"services":          svcs,
		"isolation_enabled": isoEnabled,
		"checkin_ttl":       checkinTTL,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal registration payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/css/register", cssURL)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create registration request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-API-Token", token)
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
			},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		var errResp struct {
			Error string `json:"error"`
		}
		if jsonErr := json.Unmarshal(respBody, &errResp); jsonErr == nil && errResp.Error != "" {
			return fmt.Errorf("server rejected connection (HTTP %d): %s", resp.StatusCode, errResp.Error)
		}
		return fmt.Errorf("server rejected connection (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var respData struct {
		Status       string          `json:"status"`
		Acknowledged bool            `json:"acknowledged"`
		Message      string          `json:"message"`
		SensorID     string          `json:"sensor_id"`
		Commands     []SensorCommand `json:"commands"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return fmt.Errorf("invalid server response: %w", err)
	}

	if respData.Status != "ok" && !respData.Acknowledged {
		return fmt.Errorf("server failed to acknowledge connection: %s", respData.Message)
	}

	// Successfully confirmed and acknowledged: update config & start routines
	configMu.Lock()
	globalConfig.IsSensorMode = true
	globalConfig.CSSURL = cssURL
	globalConfig.SensorToken = token
	globalConfig.SensorID = sensorID
	globalConfig.SensorCheckinTTL = checkinTTL
	globalConfig.CSSSkipVerify = skipVerify
	configMu.Unlock()
	updateSensorHTTPClient(skipVerify)

	startSensorBatchForwarder()
	go startSensorHeartbeatLoop()

	if len(respData.Commands) > 0 && ExecuteSensorRemoteCommandFunc != nil {
		for _, cmd := range respData.Commands {
			if err := ExecuteSensorRemoteCommandFunc(cmd); err != nil {
				syslog.Error(syslog.CategoryCSS, "Failed to execute remote sensor command %s on %s:%d: %v", cmd.Action, cmd.Protocol, cmd.Port, err)
			} else {
				syslog.Info(syslog.CategoryCSS, "Executed remote sensor command: %s %s:%d", cmd.Action, cmd.Protocol, cmd.Port)
			}
		}
	}

	syslog.InfoAlways(syslog.CategoryCSS, "Successfully connected and registered with CSS server at %s as sensor '%s' (TTL: %ds, SkipVerify: %v)", cssURL, sensorID, checkinTTL, skipVerify)
	return nil
}

func SetServerConfig(enabled bool, port int, tokenAuth bool, token string, ssl ...bool) {
	configMu.Lock()
	defer configMu.Unlock()
	globalConfig.ServerEnabled = enabled
	if port > 0 {
		globalConfig.ServerPort = port
	}
	globalConfig.TokenAuthEnabled = tokenAuth
	globalConfig.AuthToken = strings.TrimSpace(token)
	if len(ssl) > 0 {
		globalConfig.ServerSSL = ssl[0]
	}
}

// RegisterSensorWithCSS sends a registration request to the CSS server
func RegisterSensorWithCSS() error {
	configMu.RLock()
	cssURL := globalConfig.CSSURL
	token := globalConfig.SensorToken
	sensorID := globalConfig.SensorID
	configMu.RUnlock()

	return ConnectSensor(cssURL, token, sensorID)
}

var (
	heartbeatStopChan  chan struct{}
	heartbeatResetChan chan int
	heartbeatMu        sync.Mutex
)

func startSensorHeartbeatLoop() {
	heartbeatMu.Lock()
	if heartbeatStopChan != nil {
		close(heartbeatStopChan)
	}
	heartbeatStopChan = make(chan struct{})
	heartbeatResetChan = make(chan int, 1)
	stopChan := heartbeatStopChan
	resetChan := heartbeatResetChan
	heartbeatMu.Unlock()

	// Initial heartbeat immediately
	_ = SendHeartbeatToCSS()

	ttl := GetSensorCheckinTTL()
	if ttl <= 0 {
		ttl = 15
	}
	ticker := time.NewTicker(time.Duration(ttl) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-stopChan:
			return
		case newTTL := <-resetChan:
			ticker.Stop()
			if newTTL <= 0 {
				newTTL = 15
			}
			ticker = time.NewTicker(time.Duration(newTTL) * time.Second)
			_ = SendHeartbeatToCSS()
		case <-ticker.C:
			if !IsSensorMode() {
				return
			}
			_ = SendHeartbeatToCSS()
		}
	}
}

// SendHeartbeatToCSS sends periodic ping to CSS server to keep sensor active and update status
func SendHeartbeatToCSS() error {
	configMu.RLock()
	cssURL := globalConfig.CSSURL
	token := globalConfig.SensorToken
	sensorID := globalConfig.SensorID
	checkinTTL := globalConfig.SensorCheckinTTL
	configMu.RUnlock()

	if checkinTTL <= 0 {
		checkinTTL = 15
	}

	if cssURL == "" {
		return fmt.Errorf("CSS URL is not configured")
	}

	var svcs []ServiceInfo
	if GetRunningServicesFunc != nil {
		svcs = GetRunningServicesFunc()
	}

	isoEnabled := false
	if LocalIsIsolationEnabledFunc != nil {
		isoEnabled = LocalIsIsolationEnabledFunc()
	}

	sensorStatus := "Active"
	if len(svcs) == 0 {
		sensorStatus = "Idle"
	}

	payload := map[string]interface{}{
		"sensor_id":         sensorID,
		"status":            sensorStatus,
		"timestamp":         time.Now().UTC().Format(time.RFC3339),
		"services":          svcs,
		"isolation_enabled": isoEnabled,
		"checkin_ttl":       checkinTTL,
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal heartbeat payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/css/heartbeat", cssURL)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create heartbeat request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-API-Token", token)
	}

	skipVerify := globalConfig.CSSSkipVerify
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: skipVerify,
			},
		},
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		syslog.Warn(syslog.CategoryCSS, "Heartbeat failed to CSS server at %s: %v", cssURL, err)
		return fmt.Errorf("failed to send heartbeat to CSS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		syslog.Warn(syslog.CategoryCSS, "Heartbeat rejected by CSS server (%d): %s", resp.StatusCode, string(respBody))
		return fmt.Errorf("CSS server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	var respData struct {
		Status       string          `json:"status"`
		Acknowledged bool            `json:"acknowledged"`
		Commands     []SensorCommand `json:"commands"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respData); err == nil {
		if len(respData.Commands) > 0 && ExecuteSensorRemoteCommandFunc != nil {
			for _, cmd := range respData.Commands {
				if err := ExecuteSensorRemoteCommandFunc(cmd); err != nil {
					syslog.Error(syslog.CategoryCSS, "Failed to execute remote sensor command %s on %s:%d: %v", cmd.Action, cmd.Protocol, cmd.Port, err)
				} else {
					syslog.Info(syslog.CategoryCSS, "Executed remote sensor command: %s %s:%d", cmd.Action, cmd.Protocol, cmd.Port)
				}
			}
		}
	}

	return nil
}

// HandleCSSHeartbeat receives incoming heartbeat requests from sensors
func HandleCSSHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	remoteIP := extractRemoteIP(r)

	if !ValidateToken(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": "Unauthorized: invalid or missing CSS token"})
		return
	}

	var payload struct {
		SensorID         string        `json:"sensor_id"`
		Status           string        `json:"status"`
		Timestamp        string        `json:"timestamp"`
		IsolationEnabled bool          `json:"isolation_enabled"`
		Services         []ServiceInfo `json:"services"`
		CheckinTTL       int           `json:"checkin_ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || strings.TrimSpace(payload.SensorID) == "" {
		payload.SensorID = "remote-sensor"
	}
	if payload.Status == "" {
		payload.Status = "Active"
	}
	if payload.CheckinTTL <= 0 {
		payload.CheckinTTL = 15
	}

	var servicesJSON string
	if len(payload.Services) > 0 {
		if b, err := json.Marshal(payload.Services); err == nil {
			servicesJSON = string(b)
		}
	} else {
		servicesJSON = "[]"
	}

	isFirstTime := db.RegisterSensorNodeWithTTL(payload.SensorID, remoteIP, servicesJSON, payload.IsolationEnabled, payload.Status, payload.CheckinTTL)
	if isFirstTime {
		syslog.InfoAlways(syslog.CategoryCSS, "New sensor connected: '%s' (%s, Status: %s, TTL: %ds, Services: %d, Isolation: %v)", payload.SensorID, remoteIP, payload.Status, payload.CheckinTTL, len(payload.Services), payload.IsolationEnabled)
	} else {
		syslog.Info(syslog.CategoryCSS, "Received heartbeat ping from sensor '%s' (%s, Status: %s, TTL: %ds, Services: %d, Isolation: %v)", payload.SensorID, remoteIP, payload.Status, payload.CheckinTTL, len(payload.Services), payload.IsolationEnabled)
	}

	pendingCmds := PopSensorCommands(payload.SensorID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"acknowledged": true,
		"sensor_id":    payload.SensorID,
		"commands":     pendingCmds,
	})
}

// ForwardEventToCSS posts an event payload to the CSS server over HTTP using pooled connection
func ForwardEventToCSS(payload EventPayload) error {
	configMu.RLock()
	cssURL := globalConfig.CSSURL
	token := globalConfig.SensorToken
	sensorID := globalConfig.SensorID
	configMu.RUnlock()

	if cssURL == "" {
		return fmt.Errorf("CSS URL is not configured")
	}

	if payload.SensorID == "" {
		payload.SensorID = sensorID
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal event payload: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/css/event", cssURL)
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-API-Token", token)
	}

	resp, err := sensorHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send event to CSS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("CSS server returned status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// ValidateToken checks authentication token if token auth is enabled
func ValidateToken(r *http.Request) bool {
	configMu.RLock()
	tokenAuthEnabled := globalConfig.TokenAuthEnabled
	expectedToken := globalConfig.AuthToken
	configMu.RUnlock()

	if !tokenAuthEnabled || expectedToken == "" {
		return true
	}

	// Check X-API-Token header
	headerToken := r.Header.Get("X-API-Token")
	if headerToken == expectedToken {
		return true
	}

	// Check Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && (strings.EqualFold(parts[0], "Bearer") || strings.EqualFold(parts[0], "Token")) {
			if strings.TrimSpace(parts[1]) == expectedToken {
				return true
			}
		} else if strings.TrimSpace(authHeader) == expectedToken {
			return true
		}
	}

	// Check query string
	queryToken := r.URL.Query().Get("token")
	if queryToken == "" {
		queryToken = r.URL.Query().Get("api_key")
	}
	if queryToken == expectedToken {
		return true
	}

	return false
}

// Handlers for CSS HTTP endpoints

// HandleCSSRegister receives registration requests from sensors/agents
func HandleCSSRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	remoteIP := extractRemoteIP(r)

	if !ValidateToken(r) {
		logCSS("[red][!] CSS agent connection/registration unauthorized from %s[white]", remoteIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "error": "Unauthorized: invalid or missing CSS token"})
		return
	}

	var payload struct {
		SensorID         string        `json:"sensor_id"`
		Status           string        `json:"status"`
		Timestamp        string        `json:"timestamp"`
		IsolationEnabled bool          `json:"isolation_enabled"`
		Services         []ServiceInfo `json:"services"`
		CheckinTTL       int           `json:"checkin_ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || strings.TrimSpace(payload.SensorID) == "" {
		payload.SensorID = "remote-sensor"
	}
	if payload.Status == "" {
		payload.Status = "Active"
	}
	if payload.CheckinTTL <= 0 {
		payload.CheckinTTL = 15
	}

	var servicesJSON string
	if len(payload.Services) > 0 {
		if b, err := json.Marshal(payload.Services); err == nil {
			servicesJSON = string(b)
		}
	} else {
		servicesJSON = "[]"
	}

	isFirstTime := db.RegisterSensorNodeWithTTL(payload.SensorID, remoteIP, servicesJSON, payload.IsolationEnabled, payload.Status, payload.CheckinTTL)
	if isFirstTime {
		logCSSAlways("[green][+] New sensor connected & registered: sensor '%s' from %s (Status: %s, TTL: %ds, Services: %d, Isolation: %v)[white]", payload.SensorID, remoteIP, payload.Status, payload.CheckinTTL, len(payload.Services), payload.IsolationEnabled)
	} else {
		logCSS("[cyan][CSS] Agent connected & registered: sensor '%s' from %s (Status: %s, TTL: %ds, Services: %d, Isolation: %v)[white]", payload.SensorID, remoteIP, payload.Status, payload.CheckinTTL, len(payload.Services), payload.IsolationEnabled)
	}

	pendingCmds := PopSensorCommands(payload.SensorID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":       "ok",
		"acknowledged": true,
		"message":      "Sensor registered successfully",
		"sensor_id":    payload.SensorID,
		"commands":     pendingCmds,
	})
}

// HandleCSSEvent receives incoming events from sensors asynchronously
func HandleCSSEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	remoteIP := extractRemoteIP(r)

	if !ValidateToken(r) {
		logCSS("[red][!] CSS unauthorized event POST attempt from %s[white]", remoteIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized: invalid or missing CSS token"})
		return
	}

	var payload EventPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if payload.SensorID == "" {
		payload.SensorID = "remote-sensor"
	}

	if payload.SensorID != "" && payload.SensorID != "local" && db.DB != nil {
		var count int64
		db.DB.Model(&db.SensorNode{}).Where("sensor_id = ?", payload.SensorID).Count(&count)
		if count == 0 {
			db.RegisterSensorNodeWithTTL(payload.SensorID, remoteIP, "[]", false, "Active", 15)
			logCSSAlways("[green][+] New sensor connected: '%s' from %s[white]", payload.SensorID, remoteIP)
		}
	}

	switch payload.EventType {
	case "registration", "connect":
		logCSS("[cyan][CSS] Agent connected & registered: sensor '%s' from %s[white]", payload.SensorID, remoteIP)
	case "attempt":
		if payload.Attempt != nil {
			logCSS("[cyan][CSS] Event from agent '%s': Attempt [%s] %s:%d from %s[white]",
				payload.SensorID, strings.ToUpper(payload.Attempt.Protocol), payload.Attempt.RemoteIP, payload.Attempt.Port, remoteIP)
		}
	case "credential":
		if payload.Credential != nil {
			logCSS("[orange][CSS] Event from agent '%s': Credential captured [%s] %s:%s from %s[white]",
				payload.SensorID, strings.ToUpper(payload.Credential.Protocol), payload.Credential.Username, payload.Credential.Password, remoteIP)
		}
	case "command":
		if payload.Command != nil {
			logCSS("[yellow][CSS] Event from agent '%s': Command executed [%s] '%s' by '%s' from %s[white]",
				payload.SensorID, strings.ToUpper(payload.Command.Protocol), payload.Command.Command, payload.Command.Username, remoteIP)
		}
	}

	QueueEventForIngest(payload)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Event recorded"})
}

// HandleCSSBatchEvents receives incoming batches of events from sensors
func HandleCSSBatchEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	remoteIP := extractRemoteIP(r)

	if !ValidateToken(r) {
		logCSS("[red][!] CSS unauthorized batch event POST attempt from %s[white]", remoteIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized: invalid or missing CSS token"})
		return
	}

	var batch BatchEventPayload
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "Invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	if batch.SensorID == "" {
		batch.SensorID = "remote-sensor"
	}

	if batch.SensorID != "" && batch.SensorID != "local" && db.DB != nil {
		var count int64
		db.DB.Model(&db.SensorNode{}).Where("sensor_id = ?", batch.SensorID).Count(&count)
		if count == 0 {
			db.RegisterSensorNodeWithTTL(batch.SensorID, remoteIP, "[]", false, "Active", 15)
			logCSSAlways("[green][+] New sensor connected: '%s' from %s[white]", batch.SensorID, remoteIP)
		}
	}

	for _, evt := range batch.Events {
		if evt.SensorID == "" {
			evt.SensorID = batch.SensorID
		}
		QueueEventForIngest(evt)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"received": len(batch.Events),
	})
}

// HandleCSSConfig gets or updates CSS configuration
func HandleCSSConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		json.NewEncoder(w).Encode(GetConfig())
		return
	}

	if r.Method == http.MethodPost {
		var req struct {
			TokenAuthEnabled *bool   `json:"token_auth_enabled"`
			AuthToken        *string `json:"auth_token"`
			IsSensorMode     *bool   `json:"is_sensor_mode"`
			CSSURL           *string `json:"css_url"`
			CSSSkipVerify    *bool   `json:"css_skip_verify"`
			ServerSSL        *bool   `json:"server_ssl"`
			SensorToken      *string `json:"sensor_token"`
			SensorID         *string `json:"sensor_id"`
			SensorCheckinTTL *int    `json:"sensor_checkin_ttl"`
			CartoAPIKey      *string `json:"carto_api_key"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		cfg := GetConfig()
		if req.TokenAuthEnabled != nil {
			cfg.TokenAuthEnabled = *req.TokenAuthEnabled
		}
		if req.AuthToken != nil {
			cfg.AuthToken = *req.AuthToken
		}
		if req.IsSensorMode != nil {
			cfg.IsSensorMode = *req.IsSensorMode
		}
		if req.CSSURL != nil {
			cfg.CSSURL = *req.CSSURL
		}
		if req.CSSSkipVerify != nil {
			cfg.CSSSkipVerify = *req.CSSSkipVerify
		}
		if req.ServerSSL != nil {
			cfg.ServerSSL = *req.ServerSSL
		}
		if req.SensorToken != nil {
			cfg.SensorToken = *req.SensorToken
		}
		if req.SensorID != nil {
			cfg.SensorID = *req.SensorID
		}
		if req.SensorCheckinTTL != nil && *req.SensorCheckinTTL > 0 {
			cfg.SensorCheckinTTL = *req.SensorCheckinTTL
			SetSensorCheckinTTL(*req.SensorCheckinTTL)
		}
		if req.CartoAPIKey != nil {
			cfg.CartoAPIKey = *req.CartoAPIKey
		}

		UpdateConfig(cfg)
		json.NewEncoder(w).Encode(GetConfig())
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

// HandleCSSSensors returns connected sensors summary
func HandleCSSSensors(w http.ResponseWriter, r *http.Request) {
	sensors, err := db.GetSensorsList()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// For local sensor, populate current live isolation and services status if local honeypot services are running
	if !IsCSSServerRunning() {
		for i := range sensors {
			if sensors[i].SensorID == GetSensorID() || sensors[i].SensorID == "local" {
				if LocalIsIsolationEnabledFunc != nil {
					sensors[i].Isolation = LocalIsIsolationEnabledFunc()
				}
				if GetRunningServicesFunc != nil {
					svcs := GetRunningServicesFunc()
					var ssvcs []db.SensorServiceInfo
					for _, s := range svcs {
						ssvcs = append(ssvcs, db.SensorServiceInfo{
							Protocol: s.Protocol,
							Port:     s.Port,
							Status:   s.Status,
							Isolated: s.Isolated,
						})
					}
					sensors[i].Services = ssvcs
				}
			}
			db.SortSensorServices(sensors[i].Services)
		}
	} else {
		for i := range sensors {
			db.SortSensorServices(sensors[i].Services)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sensors)
}

// HandleUpdateSensor updates a sensor's metadata (display name)
func HandleUpdateSensor(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SensorID    string `json:"sensor_id"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SensorID == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Missing required sensor_id"})
		return
	}

	if err := db.UpdateSensorDisplayName(req.SensorID, req.DisplayName); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	syslog.Info(syslog.CategoryCSS, "Updated display name for sensor '%s' to '%s'", req.SensorID, req.DisplayName)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"message":      "Sensor display name updated successfully",
		"sensor_id":    req.SensorID,
		"display_name": req.DisplayName,
	})
}

// ControlSensorService executes locally or queues a remote command to start/stop a service on a sensor
func ControlSensorService(sensorID string, action string, protocol string, port int, isolated bool, profile string, ttl int) error {
	action = strings.ToLower(strings.TrimSpace(action))
	if action == "" {
		action = "start"
	}
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if port <= 0 {
		switch protocol {
		case "ssh":
			port = 2222
		case "telnet":
			port = 2323
		case "web":
			port = 8080
		case "vnc":
			port = 5900
		case "modbus":
			port = 502
		case "s7comm":
			port = 102
		default:
			port = 8000
		}
	}

	if protocol == "web" && strings.TrimSpace(profile) == "" {
		profile = "apache"
	}

	// 1. Enforce isolation validation: If isolated requested, check if sensor has isolation enabled
	isLocal := sensorID == GetSensorID() || sensorID == "local" || sensorID == ""
	var isolationSupported bool

	if isLocal {
		isolationSupported = LocalIsIsolationEnabledFunc != nil && LocalIsIsolationEnabledFunc()
	} else {
		node, err := db.GetSensorNode(sensorID)
		if err == nil && node != nil {
			isolationSupported = node.Isolation
		}
	}

	if action == "start" && isolated && !isolationSupported {
		return fmt.Errorf("container sandbox isolation is not enabled on sensor '%s'. Services cannot be started in isolated mode without active Docker/Podman isolation support.", sensorID)
	}

	// 2. Execute or queue the command
	if isLocal {
		if action == "start" {
			if LocalStartServiceFunc == nil {
				return fmt.Errorf("local service start handler not initialized")
			}
			if err := LocalStartServiceFunc(protocol, port, isolated, profile, ttl); err != nil {
				return err
			}
		} else if action == "stop" {
			if LocalStopServiceFunc == nil {
				return fmt.Errorf("local service stop handler not initialized")
			}
			if err := LocalStopServiceFunc(protocol, port); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("unknown service action: %s", action)
		}

		// Update database services snapshot for local sensor
		if GetRunningServicesFunc != nil {
			svcs := GetRunningServicesFunc()
			var sensorSvcs []db.SensorServiceInfo
			for _, s := range svcs {
				sensorSvcs = append(sensorSvcs, db.SensorServiceInfo{
					Protocol: s.Protocol,
					Port:     s.Port,
					Status:   s.Status,
					Isolated: s.Isolated,
				})
			}
			_ = db.UpdateSensorServices(sensorID, sensorSvcs)
		}

		syslog.Info(syslog.CategoryCSS, "Local service %s (port %d) action '%s' executed (TTL: %ds)", protocol, port, action, ttl)
		return nil
	}

	// Remote sensor: verify sensor registration
	node, err := db.GetSensorNode(sensorID)
	if err != nil || node == nil {
		return fmt.Errorf("sensor '%s' not found or not registered", sensorID)
	}

	// Queue command and update optimistic services list
	QueueSensorCommand(sensorID, SensorCommand{
		Action:   action,
		Protocol: protocol,
		Port:     port,
		Isolated: isolated,
		Profile:  profile,
		TTL:      ttl,
	})

	// Optimistically update sensor service record in DB
	curSvcs := db.GetSensorServices(sensorID)
	var updatedSvcs []db.SensorServiceInfo
	found := false
	for _, s := range curSvcs {
		if s.Protocol == protocol && s.Port == port {
			found = true
			if action == "start" {
				s.Status = "Running"
				s.Isolated = isolated
				updatedSvcs = append(updatedSvcs, s)
			}
			// If stop, omit
		} else {
			updatedSvcs = append(updatedSvcs, s)
		}
	}
	if !found && action == "start" {
		updatedSvcs = append(updatedSvcs, db.SensorServiceInfo{
			Protocol: protocol,
			Port:     port,
			Status:   "Running",
			Isolated: isolated,
		})
	}
	_ = db.UpdateSensorServices(sensorID, updatedSvcs)

	syslog.Info(syslog.CategoryCSS, "Queued service %s action '%s' on port %d for remote sensor '%s' (TTL: %ds)", protocol, action, port, sensorID, ttl)
	return nil
}

// HandleSensorServiceControl starts or stops a service on a sensor (with isolation verification and TTL)
func HandleSensorServiceControl(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		SensorID string `json:"sensor_id"`
		Action   string `json:"action"` // "start" or "stop"
		Protocol string `json:"protocol"`
		Port     int    `json:"port"`
		Isolated bool   `json:"isolated"`
		Profile  string `json:"profile"`
		TTL      int    `json:"ttl"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SensorID == "" || req.Protocol == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": "Missing required sensor_id or protocol"})
		return
	}

	if err := ControlSensorService(req.SensorID, req.Action, req.Protocol, req.Port, req.Isolated, req.Profile, req.TTL); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "error": err.Error()})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Service %s %sed successfully on port %d", req.Protocol, req.Action, req.Port),
	})
}

// UnifiedFeedItem represents a normalized honeypot event for feeds
type UnifiedFeedItem struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"` // "credential", "command", "attempt"
	Timestamp   time.Time `json:"timestamp"`
	SensorID    string    `json:"sensor_id"`
	Protocol    string    `json:"protocol"`
	RemoteIP    string    `json:"remote_ip"`
	Port        int       `json:"port"`
	Username    string    `json:"username,omitempty"`
	Password    string    `json:"password,omitempty"`
	Command     string    `json:"command,omitempty"`
	RawData     string    `json:"raw_data,omitempty"`
	CountryCode string    `json:"country_code,omitempty"`
	CountryName string    `json:"country_name,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	ASName      string    `json:"as_name,omitempty"`
}

func getUnifiedFeedItems(sensorFilter string, limit int) ([]UnifiedFeedItem, error) {
	items := make([]UnifiedFeedItem, 0)

	// Fetch credentials
	creds, err := db.GetAllCredentialsFilter(sensorFilter)
	if err == nil {
		for _, c := range creds {
			items = append(items, UnifiedFeedItem{
				ID:          fmt.Sprintf("cred-%d", c.ID),
				Type:        "credential",
				Timestamp:   c.CreatedAt,
				SensorID:    c.SensorID,
				Protocol:    c.Protocol,
				RemoteIP:    c.RemoteIP,
				Port:        0,
				Username:    c.Username,
				Password:    c.Password,
				CountryCode: c.CountryCode,
				CountryName: c.CountryName,
				ASN:         c.ASN,
				ASName:      c.ASName,
			})
		}
	}

	// Fetch commands
	cmds, err := db.GetRecentCommandsFilter(limit, sensorFilter)
	if err == nil {
		for _, cmd := range cmds {
			items = append(items, UnifiedFeedItem{
				ID:          fmt.Sprintf("cmd-%d", cmd.ID),
				Type:        "command",
				Timestamp:   cmd.CreatedAt,
				SensorID:    cmd.SensorID,
				Protocol:    cmd.Protocol,
				RemoteIP:    cmd.RemoteIP,
				Username:    cmd.Username,
				Command:     cmd.Command,
				CountryCode: cmd.CountryCode,
				CountryName: cmd.CountryName,
				ASN:         cmd.ASN,
				ASName:      cmd.ASName,
			})
		}
	}

	// Fetch attempts
	attempts, err := db.GetRecentAttemptsFilter(limit, sensorFilter)
	if err == nil {
		for _, a := range attempts {
			items = append(items, UnifiedFeedItem{
				ID:          fmt.Sprintf("attempt-%d", a.ID),
				Type:        "attempt",
				Timestamp:   a.CreatedAt,
				SensorID:    a.SensorID,
				Protocol:    a.Protocol,
				RemoteIP:    a.RemoteIP,
				Port:        a.Port,
				RawData:     a.RawData,
				CountryCode: a.CountryCode,
				CountryName: a.CountryName,
				ASN:         a.ASN,
				ASName:      a.ASName,
			})
		}
	}

	return items, nil
}

// HandleFeedJSON provides JSON & STIX 2.1 feed
func HandleFeedJSON(w http.ResponseWriter, r *http.Request) {
	remoteIP := extractRemoteIP(r)

	if !ValidateToken(r) {
		logCSS("[red][!] CSS unauthorized vuln feed access (/feed/json) from %s[white]", remoteIP)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	sensor := r.URL.Query().Get("sensor")
	format := r.URL.Query().Get("format")
	limit := 0
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}

	formatName := "JSON"
	if format == "stix2" || format == "stix" {
		formatName = "STIX 2.1"
	}
	logCSS("[purple][CSS] Vulnerability feed accessed: /feed/json (format: %s) from %s[white]", formatName, remoteIP)

	items, err := getUnifiedFeedItems(sensor, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	if format == "stix2" || format == "stix" {
		stixBundle := buildSTIX2Bundle(items, r)
		json.NewEncoder(w).Encode(stixBundle)
		return
	}

	json.NewEncoder(w).Encode(items)
}

// HandleFeedRSS provides RSS 2.0 XML feed
func HandleFeedRSS(w http.ResponseWriter, r *http.Request) {
	remoteIP := extractRemoteIP(r)

	if !ValidateToken(r) {
		logCSS("[red][!] CSS unauthorized vuln feed access (/feed/rss) from %s[white]", remoteIP)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	logCSS("[purple][CSS] Vulnerability feed accessed: /feed/rss (RSS 2.0) from %s[white]", remoteIP)

	sensor := r.URL.Query().Get("sensor")
	limit := 0
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	items, err := getUnifiedFeedItems(sensor, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	host := r.Host
	if host == "" {
		host = "localhost:8090"
	}
	baseURL := fmt.Sprintf("http://%s", host)

	w.Header().Set("Content-Type", "application/rss+xml; charset=utf-8")

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8" ?>` + "\n")
	sb.WriteString(`<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">` + "\n")
	sb.WriteString(`<channel>` + "\n")
	sb.WriteString(`  <title>Honeygo Threat Intelligence Feed</title>` + "\n")
	sb.WriteString(fmt.Sprintf(`  <link>%s</link>`+"\n", baseURL))
	sb.WriteString(`  <description>Real-time honeypot threat events from Honeygo Central Storage Server</description>` + "\n")
	sb.WriteString(`  <language>en-us</language>` + "\n")
	sb.WriteString(fmt.Sprintf(`  <lastBuildDate>%s</lastBuildDate>`+"\n", time.Now().Format(time.RFC1123)))

	for _, item := range items {
		title := fmt.Sprintf("[%s] %s event from %s", strings.ToUpper(item.Protocol), item.Type, item.RemoteIP)
		if item.Username != "" {
			title = fmt.Sprintf("[%s] %s user '%s' from %s", strings.ToUpper(item.Protocol), item.Type, item.Username, item.RemoteIP)
		}

		details := fmt.Sprintf("Sensor: %s&#10;Remote IP: %s&#10;Protocol: %s&#10;Port: %d", item.SensorID, item.RemoteIP, item.Protocol, item.Port)
		if item.Username != "" {
			details += fmt.Sprintf("&#10;Username: %s", item.Username)
		}
		if item.Password != "" {
			details += fmt.Sprintf("&#10;Password: %s", item.Password)
		}
		if item.Command != "" {
			details += fmt.Sprintf("&#10;Command: %s", item.Command)
		}
		if item.CountryName != "" {
			details += fmt.Sprintf("&#10;Country: %s (%s)", item.CountryName, item.CountryCode)
		}
		if item.ASN != "" {
			details += fmt.Sprintf("&#10;ASN: %s %s", item.ASN, item.ASName)
		}

		safeDetails := strings.ReplaceAll(details, "]]>", "]]]]><![CDATA[>")
		sb.WriteString(`  <item>` + "\n")
		sb.WriteString(fmt.Sprintf(`    <title>%s</title>`+"\n", xmlEscape(title)))
		sb.WriteString(fmt.Sprintf(`    <link>%s/#overview</link>`+"\n", baseURL))
		sb.WriteString(fmt.Sprintf(`    <guid isPermaLink="false">%s</guid>`+"\n", xmlEscape(item.ID)))
		sb.WriteString(fmt.Sprintf(`    <pubDate>%s</pubDate>`+"\n", item.Timestamp.Format(time.RFC1123)))
		sb.WriteString(fmt.Sprintf(`    <description><![CDATA[%s]]></description>`+"\n", safeDetails))
		sb.WriteString(`  </item>` + "\n")
	}

	sb.WriteString(`</channel>` + "\n")
	sb.WriteString(`</rss>` + "\n")

	w.Write([]byte(sb.String()))
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
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

// HandleFeedCSV provides CSV feed
func HandleFeedCSV(w http.ResponseWriter, r *http.Request) {
	remoteIP := extractRemoteIP(r)

	if !ValidateToken(r) {
		logCSS("[red][!] CSS unauthorized vuln feed access (/feed/csv) from %s[white]", remoteIP)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	logCSS("[purple][CSS] Vulnerability feed accessed: /feed/csv (CSV) from %s[white]", remoteIP)

	sensor := r.URL.Query().Get("sensor")
	limit := 0
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	items, err := getUnifiedFeedItems(sensor, limit)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="honeygo_feed.csv"`)

	writer := csv.NewWriter(w)
	_ = writer.Write([]string{
		"timestamp", "id", "type", "sensor_id", "protocol", "remote_ip", "port",
		"username", "password", "command", "country_code", "country_name", "asn", "as_name", "raw_data",
	})

	for _, item := range items {
		_ = writer.Write([]string{
			item.Timestamp.Format(time.RFC3339),
			sanitizeCSVField(item.ID),
			sanitizeCSVField(item.Type),
			sanitizeCSVField(item.SensorID),
			sanitizeCSVField(item.Protocol),
			sanitizeCSVField(item.RemoteIP),
			strconv.Itoa(item.Port),
			sanitizeCSVField(item.Username),
			sanitizeCSVField(item.Password),
			sanitizeCSVField(item.Command),
			sanitizeCSVField(item.CountryCode),
			sanitizeCSVField(item.CountryName),
			sanitizeCSVField(item.ASN),
			sanitizeCSVField(item.ASName),
			sanitizeCSVField(item.RawData),
		})
	}

	writer.Flush()
}

// TAXII 2.1 Implementation

// HandleTAXII2 handles root TAXII 2.1 and /collections routes
func HandleTAXII2(w http.ResponseWriter, r *http.Request) {
	remoteIP := extractRemoteIP(r)

	if !ValidateToken(r) {
		logCSS("[red][!] CSS unauthorized TAXII 2.1 vuln feed access (%s) from %s[white]", r.URL.Path, remoteIP)
		w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Unauthorized"})
		return
	}

	logCSS("[purple][CSS] TAXII 2.1 Vulnerability feed accessed: %s from %s[white]", r.URL.Path, remoteIP)

	w.Header().Set("Content-Type", "application/taxii+json;version=2.1")
	path := strings.TrimPrefix(r.URL.Path, "/taxii2")
	path = strings.TrimSuffix(path, "/")
	if path == "" {
		path = "/"
	}

	host := r.Host
	if host == "" {
		host = "localhost:8090"
	}
	baseURL := fmt.Sprintf("http://%s/taxii2", host)

	if path == "/" {
		// Discovery
		discovery := map[string]interface{}{
			"title":       "Honeygo Central Storage Server TAXII 2.1 Server",
			"description": "TAXII 2.1 Threat Intelligence API for Honeygo honeypot telemetry and OpenCTI ingestion",
			"contact":     "admin@honeygo.local",
			"default":     baseURL + "/collections/honeygo-events/",
			"api_roots":   []string{baseURL + "/"},
		}
		json.NewEncoder(w).Encode(discovery)
		return
	}

	if path == "/collections" {
		collections := map[string]interface{}{
			"collections": []map[string]interface{}{
				{
					"id":          "honeygo-events",
					"title":       "Honeygo Honeypot Attack Events",
					"description": "Observed threat actor credentials, commands, and network scans from Honeygo sensors",
					"can_read":    true,
					"can_write":   false,
					"media_types": []string{"application/stix+json;version=2.1"},
				},
			},
		}
		json.NewEncoder(w).Encode(collections)
		return
	}

	if strings.HasPrefix(path, "/collections/honeygo-events") || path == "/objects" {
		sensor := r.URL.Query().Get("sensor")
		limit := 0
		if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
				limit = l
			}
		}
		items, err := getUnifiedFeedItems(sensor, limit)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		stixBundle := buildSTIX2Bundle(items, r)
		json.NewEncoder(w).Encode(stixBundle)
		return
	}

	http.NotFound(w, r)
}

func buildSTIX2Bundle(items []UnifiedFeedItem, r *http.Request) map[string]interface{} {
	now := time.Now().Format(time.RFC3339)
	objects := make([]map[string]interface{}, 0)

	// Identity object
	objects = append(objects, map[string]interface{}{
		"type":           "identity",
		"spec_version":   "2.1",
		"id":             "identity--438992f0-c55a-4cf3-a740-10bfdfa0248a",
		"created":        now,
		"modified":       now,
		"name":           "Honeygo Central Storage Server",
		"identity_class": "system",
		"description":    "Automated honeypot sensor network feed",
	})

	for idx, item := range items {
		ts := item.Timestamp.Format(time.RFC3339)

		// Observed Data Object
		indicatorID := fmt.Sprintf("indicator--%08d-0000-0000-0000-%012d", idx+1, idx+1)
		observedDataID := fmt.Sprintf("observed-data--%08d-0000-0000-0000-%012d", idx+1, idx+1)

		description := fmt.Sprintf("Attacker from %s (%s) targeting %s on port %d [Sensor: %s]",
			item.RemoteIP, item.CountryName, item.Protocol, item.Port, item.SensorID)
		if item.Username != "" {
			description += fmt.Sprintf(" User: %s Pass: %s", item.Username, item.Password)
		}
		if item.Command != "" {
			description += fmt.Sprintf(" Cmd: %s", item.Command)
		}

		pattern := fmt.Sprintf("[ipv4-addr:value = '%s']", item.RemoteIP)

		// Indicator object (OpenCTI compatible)
		indicator := map[string]interface{}{
			"type":          "indicator",
			"spec_version":  "2.1",
			"id":            indicatorID,
			"created":       ts,
			"modified":      ts,
			"name":          fmt.Sprintf("Honeypot IP: %s (%s)", item.RemoteIP, item.Protocol),
			"description":   description,
			"pattern":       pattern,
			"pattern_type":  "stix",
			"valid_from":    ts,
			"indicator_types": []string{"malicious-activity"},
			"created_by_ref": "identity--438992f0-c55a-4cf3-a740-10bfdfa0248a",
		}
		objects = append(objects, indicator)

		// Observed Data object
		observedData := map[string]interface{}{
			"type":               "observed-data",
			"spec_version":       "2.1",
			"id":                 observedDataID,
			"created":            ts,
			"modified":           ts,
			"first_observed":     ts,
			"last_observed":      ts,
			"number_observed":    1,
			"created_by_ref":     "identity--438992f0-c55a-4cf3-a740-10bfdfa0248a",
			"object_refs":        []string{indicatorID},
		}
		objects = append(objects, observedData)
	}

	return map[string]interface{}{
		"type":         "bundle",
		"id":           fmt.Sprintf("bundle--%d", time.Now().UnixNano()),
		"spec_version": "2.1",
		"objects":      objects,
	}
}

// RegisterRoutes attaches all CSS and Feed routes to an http.ServeMux
func RegisterRoutes(mux *http.ServeMux) {
	wrap := func(pattern string, handler http.HandlerFunc) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "no-referrer")
			handler(w, r)
		})
	}

	wrap("/api/css/register", HandleCSSRegister)
	wrap("/api/css/heartbeat", HandleCSSHeartbeat)
	wrap("/api/css/event", HandleCSSEvent)
	wrap("/api/css/events/batch", HandleCSSBatchEvents)
	wrap("/api/css/config", HandleCSSConfig)
	wrap("/api/css/sensors", HandleCSSSensors)
	wrap("/api/css/sensors/update", HandleUpdateSensor)
	wrap("/api/css/sensors/service", HandleSensorServiceControl)
	wrap("/feed/json", HandleFeedJSON)
	wrap("/feed/rss", HandleFeedRSS)
	wrap("/feed/csv", HandleFeedCSV)
	wrap("/taxii2/", HandleTAXII2)
	wrap("/taxii2", HandleTAXII2)
	wrap("/collections/", HandleTAXII2)
	wrap("/collections", HandleTAXII2)
}
