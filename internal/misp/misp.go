package misp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"honeygo/internal/db"
	"honeygo/internal/syslog"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	url        string
	apiKey     string
	skipVerify bool
	logger     io.Writer
}

type MispEventLog struct {
	ID          int64     `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	Protocol    string    `json:"protocol"`
	EventType   string    `json:"event_type"`
	Info        string    `json:"info"`
	RemoteIP    string    `json:"remote_ip"`
	AttrCount   int       `json:"attr_count"`
	ThreatLevel string    `json:"threat_level"`
	Status      string    `json:"status"` // "SUCCESS", "FAILED"
	StatusCode  int       `json:"status_code"`
	LatencyMs   int64     `json:"latency_ms"`
	Error       string    `json:"error,omitempty"`
}

type StatusResponse struct {
	Enabled      bool           `json:"enabled"`
	URL          string         `json:"url"`
	APIKeyMasked string         `json:"api_key_masked"`
	SkipVerify   bool           `json:"skip_verify"`
	TotalPushed  int64          `json:"total_pushed"`
	TotalFailed  int64          `json:"total_failed"`
	LastPushedAt *time.Time     `json:"last_pushed_at"`
	LastError    string         `json:"last_error,omitempty"`
	RecentEvents []MispEventLog `json:"recent_events"`
	SensorMode   bool           `json:"sensor_mode"`
}

type TestResult struct {
	Success   bool   `json:"success"`
	Message   string `json:"message"`
	Version   string `json:"version,omitempty"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

var (
	globalClient  *Client
	clientMu      sync.RWMutex
	globalLogger  io.Writer
	cfgURL        string
	cfgAPIKey     string
	cfgSkipVerify bool
	eventSeq      int64
	totalPushed   int64
	totalFailed   int64
	lastPushedAt  *time.Time
	lastErrorMsg  string
	recentEvents  []MispEventLog
	eventLogMu    sync.RWMutex
	maxEventLogs  = 60
)

func init() {
	db.OnCredentialRecorded = PushCredential
	db.OnCommandRecorded = PushCommand
}

func cleanConfigString(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		s = s[1 : len(s)-1]
	}
	return strings.TrimSpace(s)
}

func MaskAPIKey(key string) string {
	key = cleanConfigString(key)
	if key == "" {
		return ""
	}
	if len(key) <= 6 {
		return "******"
	}
	return key[:3] + "..." + key[len(key)-3:]
}

func IsMaskedKey(key, existingKey string) bool {
	key = cleanConfigString(key)
	if key == "" {
		return false
	}
	if strings.Contains(key, "...") || strings.Contains(key, "***") || strings.Contains(key, "*") {
		return true
	}
	if existingKey != "" && key == MaskAPIKey(existingKey) {
		return true
	}
	return false
}

// Init configures and enables MISP integration (identical to CLI /misp command).
// When url or apiKey is empty, it disables the active client while preserving saved settings for the UI.
func Init(url, apiKey string, skipVerify bool, logger io.Writer) {
	clientMu.Lock()
	defer clientMu.Unlock()

	url = cleanConfigString(url)
	apiKey = cleanConfigString(apiKey)
	if logger != nil {
		globalLogger = logger
	}

	if url != "" {
		cfgURL = strings.TrimSuffix(url, "/")
	}
	if apiKey != "" && !IsMaskedKey(apiKey, cfgAPIKey) {
		cfgAPIKey = apiKey
	}
	cfgSkipVerify = skipVerify

	if url == "" || apiKey == "" || cfgURL == "" || cfgAPIKey == "" {
		globalClient = nil
		return
	}

	globalClient = &Client{
		url:        cfgURL,
		apiKey:     cfgAPIKey,
		skipVerify: cfgSkipVerify,
		logger:     globalLogger,
	}
}

func Disable() {
	clientMu.Lock()
	defer clientMu.Unlock()
	globalClient = nil
}

func IsEnabled() bool {
	clientMu.RLock()
	defer clientMu.RUnlock()
	return globalClient != nil
}

func GetConfig() (string, string, bool) {
	clientMu.RLock()
	defer clientMu.RUnlock()
	return cfgURL, cfgAPIKey, cfgSkipVerify
}

func SetLogger(w io.Writer) {
	clientMu.Lock()
	defer clientMu.Unlock()
	globalLogger = w
	if globalClient != nil {
		globalClient.logger = w
	}
}

func GetStatus() StatusResponse {
	clientMu.RLock()
	url := cfgURL
	maskedKey := MaskAPIKey(cfgAPIKey)
	skipVerify := cfgSkipVerify
	enabled := globalClient != nil
	clientMu.RUnlock()

	eventLogMu.RLock()
	defer eventLogMu.RUnlock()

	eventsCopy := make([]MispEventLog, len(recentEvents))
	copy(eventsCopy, recentEvents)

	isSensor := false
	if db.IsSensorModeFunc != nil {
		isSensor = db.IsSensorModeFunc()
	}

	return StatusResponse{
		Enabled:      enabled,
		URL:          url,
		APIKeyMasked: maskedKey,
		SkipVerify:   skipVerify,
		TotalPushed:  atomic.LoadInt64(&totalPushed),
		TotalFailed:  atomic.LoadInt64(&totalFailed),
		LastPushedAt: lastPushedAt,
		LastError:    lastErrorMsg,
		RecentEvents: eventsCopy,
		SensorMode:   isSensor,
	}
}

func recordEventLog(entry MispEventLog) {
	eventLogMu.Lock()
	defer eventLogMu.Unlock()

	entry.ID = atomic.AddInt64(&eventSeq, 1)
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	recentEvents = append([]MispEventLog{entry}, recentEvents...)
	if len(recentEvents) > maxEventLogs {
		recentEvents = recentEvents[:maxEventLogs]
	}

	if entry.Status == "SUCCESS" {
		atomic.AddInt64(&totalPushed, 1)
		now := time.Now()
		lastPushedAt = &now
	} else {
		atomic.AddInt64(&totalFailed, 1)
		lastErrorMsg = entry.Error
	}
}

func (c *Client) log(format string, a ...interface{}) {
	if c.logger != nil {
		fmt.Fprintf(c.logger, "[purple][MISP] "+format+"[white]\n", a...)
	}
}

type MispAttribute struct {
	Type     string `json:"type"`
	Value    string `json:"value"`
	ToIds    bool   `json:"to_ids"`
	Category string `json:"category"`
	Comment  string `json:"comment,omitempty"`
}

type MispEvent struct {
	Info          string          `json:"info"`
	ThreatLevelID string          `json:"threat_level_id"`
	Analysis      string          `json:"analysis"`
	Distribution  string          `json:"distribution"`
	Attribute     []MispAttribute `json:"Attribute"`
}

type MispRequest struct {
	Event MispEvent `json:"Event"`
}

func PushCredential(protocol, remoteIP, username, password string) {
	clientMu.RLock()
	c := globalClient
	clientMu.RUnlock()

	if c == nil || (db.IsSensorModeFunc != nil && db.IsSensorModeFunc()) {
		return
	}
	go c.pushCredential(protocol, remoteIP, username, password)
}

func PushWebRequest(remoteIP string, port int, requestStr string, username, password string) {
	clientMu.RLock()
	c := globalClient
	clientMu.RUnlock()

	if c == nil || (db.IsSensorModeFunc != nil && db.IsSensorModeFunc()) {
		return
	}
	go c.pushWebRequest(remoteIP, port, requestStr, username, password)
}

func PushCommand(protocol, remoteIP, username, command string) {
	clientMu.RLock()
	c := globalClient
	clientMu.RUnlock()

	if c == nil || (db.IsSensorModeFunc != nil && db.IsSensorModeFunc()) {
		return
	}
	go c.pushCommand(protocol, remoteIP, username, command)
}

func (c *Client) sendToMISP(payload MispRequest, protocol, eventType, remoteIP string) (int, error) {
	start := time.Now()
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		c.log("Error marshalling payload: %v", err)
		recordEventLog(MispEventLog{
			Timestamp:   time.Now(),
			Protocol:    protocol,
			EventType:   eventType,
			Info:        payload.Event.Info,
			RemoteIP:    remoteIP,
			AttrCount:   len(payload.Event.Attribute),
			ThreatLevel: payload.Event.ThreatLevelID,
			Status:      "FAILED",
			LatencyMs:   time.Since(start).Milliseconds(),
			Error:       fmt.Sprintf("JSON marshal error: %v", err),
		})
		return 0, err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: c.skipVerify},
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   15 * time.Second,
	}

	reqUrl := fmt.Sprintf("%s/events", c.url)
	req, err := http.NewRequest("POST", reqUrl, bytes.NewBuffer(jsonBytes))
	if err != nil {
		c.log("Error creating request: %v", err)
		syslog.Error(syslog.CategoryMISP, "Failed to create MISP request: %v", err)
		recordEventLog(MispEventLog{
			Timestamp:   time.Now(),
			Protocol:    protocol,
			EventType:   eventType,
			Info:        payload.Event.Info,
			RemoteIP:    remoteIP,
			AttrCount:   len(payload.Event.Attribute),
			ThreatLevel: payload.Event.ThreatLevelID,
			Status:      "FAILED",
			LatencyMs:   time.Since(start).Milliseconds(),
			Error:       fmt.Sprintf("Request build error: %v", err),
		})
		return 0, err
	}

	// Set standard headers accepted by MISP, PyMISP, Apache, and Nginx
	req.Header.Set("Authorization", c.apiKey)
	req.Header.Set("X-API-KEY", c.apiKey)
	req.Header.Set("auth", c.apiKey)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		c.log("Failed to connect to server: %v", err)
		syslog.Warn(syslog.CategoryMISP, "Failed to connect to MISP server at %s: %v", c.url, err)
		recordEventLog(MispEventLog{
			Timestamp:   time.Now(),
			Protocol:    protocol,
			EventType:   eventType,
			Info:        payload.Event.Info,
			RemoteIP:    remoteIP,
			AttrCount:   len(payload.Event.Attribute),
			ThreatLevel: payload.Event.ThreatLevelID,
			Status:      "FAILED",
			LatencyMs:   latency,
			Error:       fmt.Sprintf("Connection failed: %v", err),
		})
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		errMsg := fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))
		c.log("Server returned error status %d: %s", resp.StatusCode, string(bodyBytes))
		syslog.Warn(syslog.CategoryMISP, "MISP server rejected event [%s]: %s", payload.Event.Info, errMsg)
		recordEventLog(MispEventLog{
			Timestamp:   time.Now(),
			Protocol:    protocol,
			EventType:   eventType,
			Info:        payload.Event.Info,
			RemoteIP:    remoteIP,
			AttrCount:   len(payload.Event.Attribute),
			ThreatLevel: payload.Event.ThreatLevelID,
			Status:      "FAILED",
			StatusCode:  resp.StatusCode,
			LatencyMs:   latency,
			Error:       errMsg,
		})
		return resp.StatusCode, fmt.Errorf("%s", errMsg)
	}

	c.log("Successfully pushed event to server: %s", payload.Event.Info)
	syslog.Info(syslog.CategoryMISP, "Successfully pushed threat event to MISP: %s (HTTP %d, %dms)", payload.Event.Info, resp.StatusCode, latency)
	recordEventLog(MispEventLog{
		Timestamp:   time.Now(),
		Protocol:    protocol,
		EventType:   eventType,
		Info:        payload.Event.Info,
		RemoteIP:    remoteIP,
		AttrCount:   len(payload.Event.Attribute),
		ThreatLevel: payload.Event.ThreatLevelID,
		Status:      "SUCCESS",
		StatusCode:  resp.StatusCode,
		LatencyMs:   latency,
	})
	return resp.StatusCode, nil
}

func (c *Client) pushCredential(protocol, remoteIP, username, password string) {
	ip := stripPort(remoteIP)
	attributes := []MispAttribute{
		{
			Type:     "ip-src",
			Value:    ip,
			ToIds:    true,
			Category: "Network activity",
			Comment:  "Attacker Source IP",
		},
		{
			Type:     "username",
			Value:    username,
			ToIds:    false,
			Category: "Targeting data",
			Comment:  "Brute-force Username Attempted",
		},
		{
			Type:     "password",
			Value:    password,
			ToIds:    false,
			Category: "Targeting data",
			Comment:  "Brute-force Password Attempted",
		},
	}

	payload := MispRequest{
		Event: MispEvent{
			Info:          fmt.Sprintf("Honeygo Honeypot Alert - %s credential brute-force from %s", protocol, ip),
			ThreatLevelID: "3", // Low
			Analysis:      "1", // Ongoing
			Distribution:  "0", // This organisation only
			Attribute:     attributes,
		},
	}

	c.sendToMISP(payload, protocol, "Credential", ip)
}

func (c *Client) pushWebRequest(remoteIP string, port int, requestStr string, username, password string) {
	ip := stripPort(remoteIP)
	uri := extractURI(requestStr)
	userAgent := extractHeader(requestStr, "User-Agent")

	attributes := []MispAttribute{
		{
			Type:     "ip-src",
			Value:    ip,
			ToIds:    true,
			Category: "Network activity",
			Comment:  "Attacker Source IP",
		},
		{
			Type:     "text",
			Value:    requestStr,
			ToIds:    false,
			Category: "Other",
			Comment:  "Raw HTTP Request Payload",
		},
	}

	if uri != "" {
		attributes = append(attributes, MispAttribute{
			Type:     "uri",
			Value:    uri,
			ToIds:    true,
			Category: "Network activity",
			Comment:  "Scanned URI Path",
		})
	}

	if userAgent != "" {
		attributes = append(attributes, MispAttribute{
			Type:     "user-agent",
			Value:    userAgent,
			ToIds:    false,
			Category: "Payload delivery",
			Comment:  "Scanner User-Agent",
		})
	}

	if username != "" {
		attributes = append(attributes, MispAttribute{
			Type:     "username",
			Value:    username,
			ToIds:    false,
			Category: "Targeting data",
			Comment:  "Web login captured username",
		})
	}

	if password != "" {
		attributes = append(attributes, MispAttribute{
			Type:     "password",
			Value:    password,
			ToIds:    false,
			Category: "Targeting data",
			Comment:  "Web login captured password",
		})
	}

	info := fmt.Sprintf("Honeygo Honeypot Alert - HTTP scanning from %s on port %d", ip, port)
	if username != "" {
		info = fmt.Sprintf("Honeygo Honeypot Alert - HTTP credentials captured from %s on port %d", ip, port)
	}

	payload := MispRequest{
		Event: MispEvent{
			Info:          info,
			ThreatLevelID: "3", // Low
			Analysis:      "1", // Ongoing
			Distribution:  "0", // This organisation only
			Attribute:     attributes,
		},
	}

	c.sendToMISP(payload, "web", "HTTP Scan", ip)
}

func (c *Client) pushCommand(protocol, remoteIP, username, command string) {
	ip := stripPort(remoteIP)
	attributes := []MispAttribute{
		{
			Type:     "ip-src",
			Value:    ip,
			ToIds:    true,
			Category: "Network activity",
			Comment:  "Attacker Source IP",
		},
		{
			Type:     "shell-command",
			Value:    command,
			ToIds:    false,
			Category: "Artifacts",
			Comment:  fmt.Sprintf("Command executed by %s user '%s'", protocol, username),
		},
	}

	payload := MispRequest{
		Event: MispEvent{
			Info:          fmt.Sprintf("Honeygo Honeypot Alert - %s shell command executed from %s", protocol, ip),
			ThreatLevelID: "3", // Low
			Analysis:      "1", // Ongoing
			Distribution:  "0", // This organisation only
			Attribute:     attributes,
		},
	}

	c.sendToMISP(payload, protocol, "Command", ip)
}

// TestConnection attempts to query the MISP server to verify authentication and connectivity
func TestConnection(rawURL, apiKey string, skipVerify bool) (TestResult, error) {
	rawURL = cleanConfigString(rawURL)
	apiKey = cleanConfigString(apiKey)

	if rawURL == "" {
		return TestResult{Success: false, Error: "MISP Server URL cannot be empty"}, fmt.Errorf("URL empty")
	}
	if apiKey == "" {
		return TestResult{Success: false, Error: "MISP API Key cannot be empty"}, fmt.Errorf("API key empty")
	}

	rawURL = strings.TrimSuffix(rawURL, "/")
	start := time.Now()

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
	}

	// Try MISP version endpoint first
	verURL := fmt.Sprintf("%s/servers/getVersion", rawURL)
	req, err := http.NewRequest("GET", verURL, nil)
	if err != nil {
		return TestResult{Success: false, Error: fmt.Sprintf("Invalid URL or request error: %v", err)}, err
	}
	req.Header.Set("Authorization", apiKey)
	req.Header.Set("X-API-KEY", apiKey)
	req.Header.Set("auth", apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return TestResult{
			Success:   false,
			LatencyMs: latency,
			Error:     fmt.Sprintf("Connection failed: %v", err),
		}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var verData struct {
			Version string `json:"version"`
		}
		json.NewDecoder(resp.Body).Decode(&verData)
		version := verData.Version
		if version == "" {
			version = "Connected"
		}
		return TestResult{
			Success:   true,
			Message:   "Successfully authenticated with MISP Server",
			Version:   version,
			LatencyMs: latency,
		}, nil
	}

	// Fallback to events index check
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		return TestResult{
			Success:   false,
			LatencyMs: latency,
			Error:     fmt.Sprintf("Authentication failed: HTTP %d Unauthorized / Forbidden (Invalid API Key)", resp.StatusCode),
		}, fmt.Errorf("unauthorized")
	}

	bodyBytes, _ := io.ReadAll(resp.Body)
	return TestResult{
		Success:   false,
		LatencyMs: latency,
		Error:     fmt.Sprintf("Server returned HTTP %d: %s", resp.StatusCode, string(bodyBytes)),
	}, fmt.Errorf("HTTP %d", resp.StatusCode)
}

// PushCanaryTestEvent sends a diagnostic test event to MISP to verify real event ingestion
func PushCanaryTestEvent() (TestResult, error) {
	clientMu.RLock()
	c := globalClient
	url := cfgURL
	key := cfgAPIKey
	skip := cfgSkipVerify
	clientMu.RUnlock()

	if key == "" || url == "" {
		return TestResult{Success: false, Error: "MISP client is not configured (missing URL or API Key)"}, fmt.Errorf("missing config")
	}

	// If disabled or uninitialized, create a temporary client for canary test
	activeClient := c
	if activeClient == nil {
		activeClient = &Client{
			url:        url,
			apiKey:     key,
			skipVerify: skip,
			logger:     globalLogger,
		}
	}

	payload := MispRequest{
		Event: MispEvent{
			Info:          fmt.Sprintf("Honeygo Connectivity Test Event - %s", time.Now().Format("2006-01-02 15:04:05")),
			ThreatLevelID: "3", // Low
			Analysis:      "0", // Initial
			Distribution:  "0", // Organisation only
			Attribute: []MispAttribute{
				{
					Type:     "text",
					Value:    "Honeygo honeypot diagnostic probe",
					ToIds:    false,
					Category: "Other",
					Comment:  "Verification Canary",
				},
				{
					Type:     "ip-src",
					Value:    "127.0.0.1",
					ToIds:    false,
					Category: "Network activity",
					Comment:  "Loopback Test Indicator",
				},
			},
		},
	}

	code, err := activeClient.sendToMISP(payload, "canary", "Test Canary", "127.0.0.1")
	if err != nil {
		return TestResult{Success: false, Error: fmt.Sprintf("Dispatch failed: %v", err)}, err
	}
	return TestResult{
		Success: true,
		Message: fmt.Sprintf("Canary event successfully created in MISP (HTTP %d)", code),
	}, nil
}

func stripPort(addr string) string {
	return db.ExtractIP(addr)
}

func extractURI(requestStr string) string {
	parts := strings.SplitN(requestStr, "\n", 2)
	if len(parts) > 0 {
		firstLine := strings.TrimSpace(parts[0])
		words := strings.Split(firstLine, " ")
		if len(words) >= 2 {
			return words[1]
		}
	}
	return ""
}

func extractHeader(requestStr, headerName string) string {
	lines := strings.Split(requestStr, "\r\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), strings.ToLower(headerName)+": ") {
			return strings.TrimSpace(line[len(headerName)+2:])
		}
	}
	return ""
}
