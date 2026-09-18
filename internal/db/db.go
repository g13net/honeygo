package db

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"honeygo/internal/alerting"
	"log"
	"math"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	IsSensorModeFunc func() bool
	GetSensorIDFunc   func() string
	ForwardEventFunc  func(eventType string, data interface{}) error

	OnCredentialRecorded func(protocol, remoteIP, username, password string)
	OnCommandRecorded    func(protocol, remoteIP, username, command string)
)

var GeoResolver interface {
	Resolve(ip string) (string, string, string, string, string)
}

func ExtractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

type Attempt struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `gorm:"index:idx_attempts_sensor_created,priority:2;index:idx_attempts_created;index:idx_attempts_ip_created,priority:2;index:idx_attempts_ip_proto_created,priority:3;index:idx_attempts_sensor_ip_created,priority:3;index:idx_attempts_proto_created,priority:2" json:"created_at"`
	SensorID    string    `gorm:"index:idx_attempts_sensor_created,priority:1;index:idx_attempts_sensor;index:idx_attempts_sensor_ip_created,priority:1;default:'local'" json:"sensor_id"`
	Protocol    string    `gorm:"index:idx_attempts_protocol;index:idx_attempts_ip_proto_created,priority:2;index:idx_attempts_proto_created,priority:1" json:"protocol"`
	RemoteIP    string    `gorm:"index:idx_attempts_remote_ip;index:idx_attempts_ip_created,priority:1;index:idx_attempts_ip_proto_created,priority:1;index:idx_attempts_sensor_ip_created,priority:2" json:"remote_ip"`
	Port        int       `json:"port"`
	RawData     string    `json:"raw_data"`
	CountryCode string    `gorm:"index:idx_attempts_country_code" json:"country_code"`
	CountryName string    `json:"country_name"`
	ASN         string    `json:"asn"`
	ASName      string    `json:"as_name"`
	Netblock    string    `json:"netblock"`
}


func getActiveSensorID() string {
	if GetSensorIDFunc != nil {
		if id := GetSensorIDFunc(); id != "" {
			return id
		}
	}
	return "local"
}

func GetActiveSensorID() string {
	return getActiveSensorID()
}

// ApplySensorFilter applies the sensor filter to a GORM query.
// If sensor is "all" or "", no filter is applied (combines all sensor stats).
// If sensor is "local", it matches "local", "", or NULL.
// Otherwise, it matches the exact sensor_id.
func ApplySensorFilter(tx *gorm.DB, sensor string) *gorm.DB {
	if tx == nil {
		return tx
	}
	if sensor == "" || sensor == "all" {
		return tx
	}
	if sensor == "local" {
		return tx.Where("sensor_id = 'local' OR sensor_id = '' OR sensor_id IS NULL")
	}
	return tx.Where("sensor_id = ?", sensor)
}

// SensorWhereClause returns a raw SQL WHERE snippet and corresponding arguments for SQL filtering.
func SensorWhereClause(sensor, columnPrefix string) (string, []interface{}) {
	if sensor == "" || sensor == "all" {
		return "", nil
	}
	col := "sensor_id"
	if columnPrefix != "" {
		col = columnPrefix + ".sensor_id"
	}
	if sensor == "local" {
		return fmt.Sprintf(" AND (%s = 'local' OR %s = '' OR %s IS NULL)", col, col, col), nil
	}
	return fmt.Sprintf(" AND %s = ?", col), []interface{}{sensor}
}

func isSensorModeActive() bool {
	if IsSensorModeFunc != nil {
		return IsSensorModeFunc()
	}
	return false
}

func (a *Attempt) BeforeCreate(tx *gorm.DB) (err error) {
	if a.Protocol != "" {
		a.Protocol = strings.ToLower(strings.TrimSpace(a.Protocol))
	}
	a.RemoteIP = ExtractIP(a.RemoteIP)
	if a.SensorID == "" {
		a.SensorID = getActiveSensorID()
	}
	if a.CountryCode == "" && GeoResolver != nil {
		a.CountryCode, a.CountryName, a.ASN, a.ASName, a.Netblock = GeoResolver.Resolve(a.RemoteIP)
	}
	return nil
}

type Credential struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `gorm:"index:idx_creds_sensor_created,priority:2;index:idx_creds_created;index:idx_creds_ip_created,priority:2;index:idx_creds_sensor_ip_created,priority:3" json:"created_at"`
	SensorID    string    `gorm:"index:idx_creds_sensor_created,priority:1;index:idx_creds_sensor;index:idx_creds_sensor_ip_created,priority:1;default:'local'" json:"sensor_id"`
	Protocol    string    `gorm:"index:idx_creds_protocol" json:"protocol"`
	RemoteIP    string    `gorm:"index:idx_creds_remote_ip;index:idx_creds_ip_created,priority:1;index:idx_creds_sensor_ip_created,priority:2" json:"remote_ip"`
	Username    string    `gorm:"index:idx_creds_username" json:"username"`
	Password    string    `gorm:"index:idx_creds_password" json:"password"`
	CountryCode string    `gorm:"index:idx_creds_country_code" json:"country_code"`
	CountryName string    `json:"country_name"`
	ASN         string    `json:"asn"`
	ASName      string    `json:"as_name"`
	Netblock    string    `json:"netblock"`
}

type Command struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `gorm:"index:idx_cmds_sensor_created,priority:2;index:idx_cmds_created;index:idx_cmds_ip_created,priority:2;index:idx_cmds_sensor_ip_created,priority:3" json:"created_at"`
	SensorID    string    `gorm:"index:idx_cmds_sensor_created,priority:1;index:idx_cmds_sensor;index:idx_cmds_sensor_ip_created,priority:1;default:'local'" json:"sensor_id"`
	Protocol    string    `gorm:"index:idx_cmds_protocol" json:"protocol"`
	RemoteIP    string    `gorm:"index:idx_cmds_remote_ip;index:idx_cmds_ip_created,priority:1;index:idx_cmds_sensor_ip_created,priority:2" json:"remote_ip"`
	Username    string    `gorm:"index:idx_cmds_username" json:"username"`
	Command     string    `json:"command"`
	CountryCode string    `gorm:"index:idx_cmds_country_code" json:"country_code"`
	CountryName string    `json:"country_name"`
	ASN         string    `json:"asn"`
	ASName      string    `json:"as_name"`
	Netblock    string    `json:"netblock"`
}

type SensorServiceInfo struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Status   string `json:"status"`
	Isolated bool   `json:"isolated"`
}

type SensorNode struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	SensorID     string    `gorm:"uniqueIndex;not null" json:"sensor_id"`
	DisplayName  string    `json:"display_name"`
	RemoteIP     string    `json:"remote_ip"`
	ServicesJSON string    `gorm:"type:text" json:"services_json"`
	Isolation    bool      `json:"isolation"`
	Status       string    `json:"status" gorm:"default:'Active'"`
	CheckinTTL   int       `json:"checkin_ttl" gorm:"default:15"`
	LastSeen     time.Time `gorm:"index:idx_sensor_nodes_last_seen" json:"last_seen"`
	CreatedAt    time.Time `json:"created_at"`
}

type ReconTarget struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	IP            string    `gorm:"uniqueIndex;not null" json:"ip"`
	Domain        string    `json:"domain"`
	SourceType    string    `json:"source_type"` // "c2_dropper", "canary_hit", "manual"
	SourceContext string    `gorm:"type:text" json:"source_context"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
	HitCount      int       `json:"hit_count" gorm:"default:1"`
	CountryCode   string    `json:"country_code"`
	CountryName   string    `json:"country_name"`
	ASN           string    `json:"asn"`
	ASName        string    `json:"as_name"`
	ReverseDNS    string    `json:"reverse_dns"`
	OpenPorts     string    `gorm:"type:text" json:"open_ports"`   // JSON array of ints, e.g. "[80, 8080, 22]"
	BannersJSON   string    `gorm:"type:text" json:"banners_json"` // JSON map of port -> banner
	RiskScore     int       `json:"risk_score"`                    // 0 to 100
	Tags          string    `json:"tags"`                          // comma-separated tags
	Status        string    `json:"status" gorm:"default:'pending'"` // "pending", "scanning", "completed", "failed"
	LastScan      time.Time `json:"last_scan"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type SystemSetting struct {
	Key       string    `gorm:"primaryKey" json:"key"`
	Value     string    `gorm:"type:text" json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

func SetSystemSetting(key, value string) error {
	if DB == nil {
		return nil
	}
	setting := SystemSetting{
		Key:       key,
		Value:     value,
		UpdatedAt: time.Now(),
	}
	return DB.Save(&setting).Error
}

func GetSystemSetting(key string) (string, bool) {
	if DB == nil {
		return "", false
	}
	var setting SystemSetting
	if err := DB.First(&setting, "key = ?", key).Error; err != nil {
		return "", false
	}
	return setting.Value, true
}

var (
	sensorLastUpdatedMu sync.RWMutex
	sensorLastUpdated   = make(map[string]time.Time)
	sensorRegisterMu    sync.Mutex
)

func RegisterSensorNode(sensorID string, remoteIP string, servicesJSON ...string) bool {
	if DB == nil || sensorID == "" || sensorID == "local" {
		return false
	}
	var sj string
	if len(servicesJSON) > 0 {
		sj = servicesJSON[0]
	}
	return RegisterSensorNodeWithTTL(sensorID, remoteIP, sj, false, "Active", 15)
}

func RegisterSensorNodeWithIsolation(sensorID string, remoteIP string, servicesJSON string, isolation bool) bool {
	return RegisterSensorNodeWithTTL(sensorID, remoteIP, servicesJSON, isolation, "Active", 15)
}

func RegisterSensorNodeWithStatus(sensorID string, remoteIP string, servicesJSON string, isolation bool, status string) bool {
	return RegisterSensorNodeWithTTL(sensorID, remoteIP, servicesJSON, isolation, status, 15)
}

func RegisterSensorNodeWithTTL(sensorID string, remoteIP string, servicesJSON string, isolation bool, status string, checkinTTL int) bool {
	if DB == nil || sensorID == "" || sensorID == "local" {
		return false
	}

	sensorLastUpdatedMu.Lock()
	sensorLastUpdated[sensorID] = time.Now()
	sensorLastUpdatedMu.Unlock()

	status = strings.TrimSpace(status)
	if status == "" {
		status = "Active"
	}
	if checkinTTL <= 0 {
		checkinTTL = 15
	}

	sensorRegisterMu.Lock()
	defer sensorRegisterMu.Unlock()

	var node SensorNode
	if err := DB.Where("sensor_id = ?", sensorID).First(&node).Error; err == nil {
		updates := map[string]interface{}{
			"remote_ip":     remoteIP,
			"isolation":     isolation,
			"status":        status,
			"checkin_ttl":   checkinTTL,
			"last_seen":     time.Now(),
			"services_json": servicesJSON,
		}
		DB.Model(&node).Updates(updates)
		return false
	} else {
		DB.Create(&SensorNode{
			SensorID:     sensorID,
			RemoteIP:     remoteIP,
			ServicesJSON: servicesJSON,
			Isolation:    isolation,
			Status:       status,
			CheckinTTL:   checkinTTL,
			LastSeen:     time.Now(),
			CreatedAt:    time.Now(),
		})
		return true
	}
}

func (c *Command) BeforeCreate(tx *gorm.DB) (err error) {
	if c.Protocol != "" {
		c.Protocol = strings.ToLower(strings.TrimSpace(c.Protocol))
	}
	c.RemoteIP = ExtractIP(c.RemoteIP)
	if c.SensorID == "" {
		c.SensorID = getActiveSensorID()
	}
	if c.CountryCode == "" && GeoResolver != nil {
		c.CountryCode, c.CountryName, c.ASN, c.ASName, c.Netblock = GeoResolver.Resolve(c.RemoteIP)
	}
	return nil
}

type GeoCache struct {
	IP          string    `gorm:"primaryKey;index:idx_geo_cache_ip" json:"ip"`
	CountryCode string    `gorm:"index:idx_geo_cache_cc" json:"country_code"`
	CountryName string    `json:"country_name"`
	ASN         string    `json:"asn"`
	ASName      string    `json:"as_name"`
	Netblock    string    `json:"netblock"`
	CreatedAt   time.Time `json:"created_at"`
}

func (c *Credential) BeforeCreate(tx *gorm.DB) (err error) {
	if c.Protocol != "" {
		c.Protocol = strings.ToLower(strings.TrimSpace(c.Protocol))
	}
	c.RemoteIP = ExtractIP(c.RemoteIP)
	if c.SensorID == "" {
		c.SensorID = getActiveSensorID()
	}
	if c.CountryCode == "" && GeoResolver != nil {
		c.CountryCode, c.CountryName, c.ASN, c.ASName, c.Netblock = GeoResolver.Resolve(c.RemoteIP)
	}
	return nil
}

// Map of hex(VNC response to all-zero challenge) -> plaintext password
var CommonVNCResponses = map[string]string{
	"946A9400266A94000C6A046ADCB42C00": "password",
	"94E2741E26E2741E0CE2C46E823E8E1E": "123456",
	"1446144694461446DC32DC325C32DC32": "admin",
	"34D66CDCDC32DC320CB4BCFC82823E1E": "vnc",
	"4CE2741E26A2D4660C969E66F43EB242": "12345678",
	"98D6BCFC7CBC7CBC0C6EB2420C6EB242": "qwerty",
}

// AfterCreate is a GORM hook that gets called after a new Credential is saved.
func (c *Credential) AfterCreate(tx *gorm.DB) (err error) {
	if isSensorModeActive() {
		return nil // Do not push Telegram alerts when connected to CSS
	}

	countryStr := ""
	if c.CountryCode != "" {
		countryStr = fmt.Sprintf("🌍 *Country:* %s %s (%s)\n", getFlagEmoji(c.CountryCode), c.CountryName, c.CountryCode)
	}

	password := c.Password
	if c.Protocol == "vnc" {
		if p, ok := CommonVNCResponses[c.Password]; ok {
			password = fmt.Sprintf("%s (`%s`)", c.Password, p)
		}
	}

	msg := fmt.Sprintf("🚨 *New Credential Captured* 🚨\n\n"+
		"📍 *Protocol:* %s\n"+
		"🌐 *Remote IP:* %s\n"+
		"%s"+
		"👤 *Username:* %s\n"+
		"🔑 *Password:* %s",
		c.Protocol, c.RemoteIP, countryStr, c.Username, password)

	// Fire and forget in a goroutine so it doesn't block the database transaction
	go alerting.SendTelegramMessage(msg)
	return nil
}

func getFlagEmoji(countryCode string) string {
	if len(countryCode) != 2 {
		return "🏴‍☠️"
	}
	r1 := rune(countryCode[0]) - 'A' + 0x1F1E6
	r2 := rune(countryCode[1]) - 'A' + 0x1F1E6
	return string(r1) + string(r2)
}

var DB *gorm.DB

func InitDB() error {
	var err error
	DB, err = gorm.Open(sqlite.Open("honeygo.db"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return err
	}

	// Optimize SQLite performance & concurrency with WAL mode and memory cache
	if sqlDB, err := DB.DB(); err == nil {
		sqlDB.SetMaxOpenConns(10)
		sqlDB.SetMaxIdleConns(5)
		sqlDB.SetConnMaxLifetime(time.Hour)

		DB.Exec("PRAGMA journal_mode = WAL;")
		DB.Exec("PRAGMA synchronous = NORMAL;")
		DB.Exec("PRAGMA busy_timeout = 5000;")
		DB.Exec("PRAGMA cache_size = -64000;") // 64MB cache
		DB.Exec("PRAGMA temp_store = MEMORY;")
		DB.Exec("PRAGMA mmap_size = 268435456;") // 256MB memory map
	}

	// Migrate the schema
	if err := DB.AutoMigrate(&Attempt{}, &Credential{}, &GeoCache{}, &Command{}, &SensorNode{}, &ReconTarget{}, &SystemSetting{}); err != nil {
		return err
	}

	// Composite indexes for sub-millisecond host queries, scan queries, and credential lookups
	compositeIndexes := []string{
		"CREATE INDEX IF NOT EXISTS idx_attempts_ip_created ON attempts(remote_ip, created_at DESC);",
		"CREATE INDEX IF NOT EXISTS idx_attempts_ip_proto_created ON attempts(remote_ip, protocol, created_at DESC);",
		"CREATE INDEX IF NOT EXISTS idx_attempts_sensor_ip_created ON attempts(sensor_id, remote_ip, created_at DESC);",
		"CREATE INDEX IF NOT EXISTS idx_attempts_proto_created ON attempts(protocol, created_at DESC);",
		"CREATE INDEX IF NOT EXISTS idx_creds_ip_created ON credentials(remote_ip, created_at DESC);",
		"CREATE INDEX IF NOT EXISTS idx_creds_sensor_ip_created ON credentials(sensor_id, remote_ip, created_at DESC);",
		"CREATE INDEX IF NOT EXISTS idx_cmds_ip_created ON commands(remote_ip, created_at DESC);",
		"CREATE INDEX IF NOT EXISTS idx_cmds_sensor_ip_created ON commands(sensor_id, remote_ip, created_at DESC);",
	}
	for _, idx := range compositeIndexes {
		DB.Exec(idx)
	}

	DB.Exec("UPDATE attempts SET protocol = LOWER(protocol) WHERE protocol != LOWER(protocol);")
	DB.Exec("UPDATE credentials SET protocol = LOWER(protocol) WHERE protocol != LOWER(protocol);")
	DB.Exec("UPDATE commands SET protocol = LOWER(protocol) WHERE protocol != LOWER(protocol);")

	StartThreatIntelWorker()

	return nil
}

var (
	threatIntelMu          sync.RWMutex
	cachedCorrelations     = make(map[string]CorrelationReport)
	cachedCorrelationsJSON = make(map[string][]byte)
	threatIntelTriggerChan = make(chan string, 200)
	threatIntelWorkerOnce  sync.Once
)

// TriggerThreatIntelUpdate signals the ongoing threat intelligence calculation engine
// that new event data has been recorded, allowing ongoing background pre-computation.
func TriggerThreatIntelUpdate(sensorID ...string) {
	s := ""
	if len(sensorID) > 0 {
		s = sensorID[0]
	}
	select {
	case threatIntelTriggerChan <- s:
	default:
	}
}

// StartThreatIntelWorker runs an ongoing background loop that continuously precalculates
// threat intelligence and correlation matrices whenever data is received.
func StartThreatIntelWorker() {
	threatIntelWorkerOnce.Do(func() {
		go func() {
			// Initial calculation on startup so data is immediately ready before user clicks
			RecomputeCachedCorrelations("")

			ticker := time.NewTicker(20 * time.Second)
			defer ticker.Stop()

			var lastRun time.Time
			const minInterval = 5 * time.Second

			for {
				select {
				case sensor := <-threatIntelTriggerChan:
					// Debounce rapid packet arrivals (2s window)
					time.Sleep(2 * time.Second)
					drainedSensors := make(map[string]bool)
					if sensor != "" {
						drainedSensors[sensor] = true
					}
				drainLoop:
					for {
						select {
						case s := <-threatIntelTriggerChan:
							if s != "" {
								drainedSensors[s] = true
							}
						default:
							break drainLoop
						}
					}

					// Cooldown check to prevent CPU spinning under continuous floods
					if elapsed := time.Since(lastRun); elapsed < minInterval {
						time.Sleep(minInterval - elapsed)
					}

					RecomputeCachedCorrelations("")
					lastRun = time.Now()

					// Only recompute sensors that are already cached/viewed by users
					threatIntelMu.RLock()
					sensorsToRefresh := make([]string, 0)
					for s := range drainedSensors {
						if s != "" && s != "all" {
							if _, exists := cachedCorrelationsJSON[s]; exists {
								sensorsToRefresh = append(sensorsToRefresh, s)
							}
						}
					}
					threatIntelMu.RUnlock()

					for _, s := range sensorsToRefresh {
						RecomputeCachedCorrelations(s)
					}

				case <-ticker.C:
					// Periodic background refresh if dirty or unpopulated
					threatIntelMu.RLock()
					isEmpty := len(cachedCorrelationsJSON[""]) == 0
					threatIntelMu.RUnlock()
					if isEmpty {
						RecomputeCachedCorrelations("")
						lastRun = time.Now()
					}
				}
			}
		}()
	})
}

// RecomputeCachedCorrelations computes the correlation report and serializes to JSON in memory.
func RecomputeCachedCorrelations(sensor string) {
	report, err := GetCorrelationReportFilter(sensor, 100)
	if err != nil {
		return
	}
	data, err := json.Marshal(report)
	if err != nil {
		return
	}

	threatIntelMu.Lock()
	cachedCorrelations[sensor] = report
	cachedCorrelationsJSON[sensor] = data
	threatIntelMu.Unlock()
}

// GetCachedCorrelationJSON returns precomputed threat intelligence JSON instantly in 0ms.
func GetCachedCorrelationJSON(sensor string) ([]byte, bool) {
	threatIntelMu.RLock()
	defer threatIntelMu.RUnlock()
	if sensor == "all" || sensor == "" {
		data, ok := cachedCorrelationsJSON[""]
		return data, ok && len(data) > 0
	}
	data, ok := cachedCorrelationsJSON[sensor]
	if ok && len(data) > 0 {
		return data, true
	}
	return nil, false
}

// SetCachedCorrelationJSON stores computed threat intelligence JSON into memory cache.
func SetCachedCorrelationJSON(sensor string, data []byte, report CorrelationReport) {
	threatIntelMu.Lock()
	defer threatIntelMu.Unlock()
	if sensor == "all" {
		sensor = ""
	}
	cachedCorrelations[sensor] = report
	cachedCorrelationsJSON[sensor] = data
}

func ClearDB() error {
	if DB == nil {
		return fmt.Errorf("database not initialized")
	}
	// Purge all tables
	if err := DB.Exec("DELETE FROM attempts").Error; err != nil {
		return err
	}
	if err := DB.Exec("DELETE FROM credentials").Error; err != nil {
		return err
	}
	if err := DB.Exec("DELETE FROM commands").Error; err != nil {
		return err
	}
	if err := DB.Exec("DELETE FROM recon_targets").Error; err != nil {
		return err
	}
	if err := DB.Exec("DELETE FROM sensor_nodes").Error; err != nil {
		return err
	}
	ClearCorrelationCache()
	return nil
}

// ClearCorrelationCache clears all in-memory precomputed threat intelligence reports.
func ClearCorrelationCache() {
	threatIntelMu.Lock()
	defer threatIntelMu.Unlock()
	cachedCorrelations = make(map[string]CorrelationReport)
	cachedCorrelationsJSON = make(map[string][]byte)
}

// RecordAttempt handles recording an attempt locally or forwarding to CSS
func RecordAttempt(a *Attempt) {
	if a == nil {
		return
	}
	a.RemoteIP = ExtractIP(a.RemoteIP)
	if a.SensorID == "" {
		a.SensorID = getActiveSensorID()
	}

	if isSensorModeActive() {
		// When connected to CSS, do NOT store logs locally in SQLite!
		if ForwardEventFunc != nil {
			go func(evt Attempt) {
				if err := ForwardEventFunc("attempt", &evt); err != nil {
					log.Printf("[!] Failed to forward attempt event to Central Storage Server: %v", err)
				}
			}(*a)
		}
		return
	}

	// Local DB storage
	if DB != nil {
		DB.Create(a)
		TriggerThreatIntelUpdate(a.SensorID)
	}
}

// RecordCredential handles recording credentials locally or forwarding to CSS
func RecordCredential(c *Credential) {
	if c == nil {
		return
	}
	c.RemoteIP = ExtractIP(c.RemoteIP)
	if c.SensorID == "" {
		c.SensorID = getActiveSensorID()
	}

	if isSensorModeActive() {
		// When connected to CSS, do NOT store logs locally in SQLite!
		if ForwardEventFunc != nil {
			go func(evt Credential) {
				if err := ForwardEventFunc("credential", &evt); err != nil {
					log.Printf("[!] Failed to forward credential event to Central Storage Server: %v", err)
				}
			}(*c)
		}
		return
	}

	// Local DB storage
	if DB != nil {
		DB.Create(c)
		TriggerThreatIntelUpdate(c.SensorID)
	}

	// Trigger registered integration callbacks (e.g. MISP threat sharing)
	if OnCredentialRecorded != nil {
		OnCredentialRecorded(c.Protocol, c.RemoteIP, c.Username, c.Password)
	}
}

// RecordCommand handles recording executed commands locally or forwarding to CSS
func RecordCommand(cmd *Command) {
	if cmd == nil {
		return
	}
	cmd.RemoteIP = ExtractIP(cmd.RemoteIP)
	if cmd.SensorID == "" {
		cmd.SensorID = getActiveSensorID()
	}

	if isSensorModeActive() {
		// When connected to CSS, do NOT store logs locally in SQLite!
		if ForwardEventFunc != nil {
			go func(evt Command) {
				if err := ForwardEventFunc("command", &evt); err != nil {
					log.Printf("[!] Failed to forward command event to Central Storage Server: %v", err)
				}
			}(*cmd)
		}
		return
	}

	// Local DB storage
	if DB != nil {
		DB.Create(cmd)
		TriggerThreatIntelUpdate(cmd.SensorID)
	}

	// Trigger registered integration callbacks (e.g. MISP threat sharing)
	if OnCommandRecorded != nil {
		OnCommandRecorded(cmd.Protocol, cmd.RemoteIP, cmd.Username, cmd.Command)
	}
}

type PasswordStat struct {
	Password string `json:"password"`
	Count    int64  `json:"count"`
}

type ProtocolStat struct {
	Protocol string `json:"protocol"`
	Count    int64  `json:"count"`
}

func GetTopPasswords(limit int) ([]PasswordStat, error) {
	return GetTopPasswordsFilter(limit, "")
}

func GetTopPasswordsFilter(limit int, sensor string) ([]PasswordStat, error) {
	var stats []PasswordStat
	query := DB.Model(&Credential{}).Select("password, count(*) as count")
	query = ApplySensorFilter(query, sensor)
	err := query.Group("password").Order("count desc").Limit(limit).Scan(&stats).Error
	return stats, err
}

func GetTopPasswordsByProtocol(protocol string, limit int) ([]PasswordStat, error) {
	var stats []PasswordStat
	err := DB.Model(&Credential{}).
		Where("protocol = ?", protocol).
		Select("password, count(*) as count").
		Group("password").
		Order("count desc").
		Limit(limit).
		Scan(&stats).Error
	return stats, err
}

func GetProtocolStats() ([]ProtocolStat, error) {
	return GetProtocolStatsFilter("")
}

func GetProtocolStatsFilter(sensor string) ([]ProtocolStat, error) {
	var stats []ProtocolStat
	query := DB.Model(&Attempt{}).Select("protocol, count(*) as count")
	query = ApplySensorFilter(query, sensor)
	err := query.Group("protocol").Order("count desc, protocol asc").Scan(&stats).Error
	return stats, err
}

func GetCredentialProtocolStats() ([]ProtocolStat, error) {
	var stats []ProtocolStat
	err := DB.Model(&Credential{}).
		Select("protocol, count(*) as count").
		Group("protocol").
		Order("count desc, protocol asc").
		Scan(&stats).Error
	return stats, err
}

func GetAllCredentials() ([]Credential, error) {
	return GetAllCredentialsFilter("")
}

func GetCredentialsSearchFilter(sensor, passwordQuery, usernameQuery, hostQuery, protocolQuery string) ([]Credential, error) {
	var creds []Credential
	query := DB.Model(&Credential{}).Order("created_at desc")
	query = ApplySensorFilter(query, sensor)
	if passwordQuery != "" {
		query = query.Where("LOWER(password) LIKE ?", "%"+strings.ToLower(passwordQuery)+"%")
	}
	if usernameQuery != "" {
		query = query.Where("LOWER(username) LIKE ?", "%"+strings.ToLower(usernameQuery)+"%")
	}
	if hostQuery != "" {
		query = query.Where("LOWER(remote_ip) LIKE ?", "%"+strings.ToLower(hostQuery)+"%")
	}
	if protocolQuery != "" {
		query = query.Where("LOWER(protocol) = ?", strings.ToLower(protocolQuery))
	}
	err := query.Find(&creds).Error
	return creds, err
}

func GetAllCredentialsFilter(sensor string) ([]Credential, error) {
	return GetCredentialsSearchFilter(sensor, "", "", "", "")
}

func GetRecentAttempts(limit int) ([]Attempt, error) {
	return GetRecentAttemptsFilter(limit, "")
}

func GetRecentAttemptsFilter(limit int, sensor string) ([]Attempt, error) {
	var attempts []Attempt
	query := DB.Model(&Attempt{}).Order("created_at desc")
	query = ApplySensorFilter(query, sensor)
	if limit > 0 {
		query = query.Limit(limit)
	}
	err := query.Find(&attempts).Error
	return attempts, err
}

type CountryStat struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Attempts    int64  `json:"attempts"`
	Credentials int64  `json:"credentials"`
}

type HostStat struct {
	RemoteIP    string `json:"remote_ip"`
	ASN         string `json:"asn"`
	ASName      string `json:"as_name"`
	CountryCode string `json:"country_code"`
	Count       int64  `json:"count"`
}

func GetTopCountries(limit int) ([]CountryStat, error) {
	return GetTopCountriesFilter(limit, "")
}

func GetTopCountriesFilter(limit int, sensor string) ([]CountryStat, error) {
	var stats []CountryStat
	sensorWhere, sensorArgs := SensorWhereClause(sensor, "")

	query := fmt.Sprintf(`
		SELECT 
			c.country_code, 
			c.country_name, 
			COALESCE(a.attempts_count, 0) as attempts, 
			COALESCE(cr.creds_count, 0) as credentials
		FROM (
			SELECT DISTINCT country_code, country_name FROM attempts WHERE country_code != '' AND country_code IS NOT NULL%s
			UNION
			SELECT DISTINCT country_code, country_name FROM credentials WHERE country_code != '' AND country_code IS NOT NULL%s
		) c
		LEFT JOIN (
			SELECT country_code, count(*) as attempts_count FROM attempts WHERE 1=1%s GROUP BY country_code
		) a ON a.country_code = c.country_code
		LEFT JOIN (
			SELECT country_code, count(*) as creds_count FROM credentials WHERE 1=1%s GROUP BY country_code
		) cr ON cr.country_code = c.country_code
		ORDER BY (attempts + credentials) DESC
		LIMIT ?
	`, sensorWhere, sensorWhere, sensorWhere, sensorWhere)

	args := []interface{}{}
	if len(sensorArgs) > 0 {
		args = append(args, sensorArgs[0], sensorArgs[0], sensorArgs[0], sensorArgs[0], limit)
	} else {
		args = append(args, limit)
	}

	err := DB.Raw(query, args...).Scan(&stats).Error
	return stats, err
}

func GetTopHosts(limit int) ([]HostStat, error) {
	return GetTopHostsFilter(limit, "")
}

func GetTopHostsFilter(limit int, sensor string) ([]HostStat, error) {
	var stats []HostStat
	query := DB.Model(&Attempt{}).
		Select("remote_ip, max(asn) as asn, max(as_name) as as_name, max(country_code) as country_code, count(*) as count")
	query = ApplySensorFilter(query, sensor)
	err := query.Group("remote_ip").Order("count desc").Limit(limit).Scan(&stats).Error
	return stats, err
}

type UsernameStat struct {
	Username string `json:"username"`
	Protocol string `json:"protocol"`
	Count    int64  `json:"count"`
}

func GetTopUsernamesByProtocol(limit int) ([]UsernameStat, error) {
	return GetTopUsernamesByProtocolFilter(limit, "")
}

func GetTopUsernamesByProtocolFilter(limit int, sensor string) ([]UsernameStat, error) {
	var stats []UsernameStat
	query := DB.Model(&Credential{}).Select("username, protocol, count(*) as count")
	query = ApplySensorFilter(query, sensor)
	err := query.Group("username, protocol").Order("count desc").Limit(limit).Scan(&stats).Error
	return stats, err
}

type NetblockStat struct {
	ASName string `json:"as_name"`
	Count  int64  `json:"count"`
}

func GetTopNetblockOwners(limit int) ([]NetblockStat, error) {
	return GetTopNetblockOwnersFilter(limit, "")
}

func GetTopNetblockOwnersFilter(limit int, sensor string) ([]NetblockStat, error) {
	var stats []NetblockStat
	query := DB.Model(&Attempt{}).
		Select("as_name, count(*) as count").
		Where("as_name != '' AND as_name != 'Unknown'")
	query = ApplySensorFilter(query, sensor)
	err := query.Group("as_name").Order("count desc").Limit(limit).Scan(&stats).Error
	return stats, err
}

type ASNCompanyTypeStat struct {
	Category    string   `json:"category"`
	AttackCount int64    `json:"attack_count"`
	UniqueIPs   int64    `json:"unique_ips"`
	Percentage  float64  `json:"percentage"`
	TopASNs     []string `json:"top_asns"`
}

func matchASNCategory(hostCat, targetCat string) bool {
	if targetCat == "" || strings.EqualFold(targetCat, "all") {
		return true
	}
	if strings.EqualFold(hostCat, targetCat) {
		return true
	}
	h := strings.ToLower(hostCat)
	t := strings.ToLower(targetCat)
	if strings.Contains(h, "cloud") && strings.Contains(t, "cloud") {
		return true
	}
	if strings.Contains(h, "crawler") && strings.Contains(t, "crawler") {
		return true
	}
	if strings.Contains(h, "isp") && strings.Contains(t, "isp") {
		return true
	}
	if strings.Contains(h, "vpn") && strings.Contains(t, "vpn") {
		return true
	}
	if strings.Contains(h, "edu") && strings.Contains(t, "edu") {
		return true
	}
	if strings.Contains(h, "enterp") && strings.Contains(t, "enterp") {
		return true
	}
	if strings.Contains(h, "private") && strings.Contains(t, "private") {
		return true
	}
	return false
}

func GetASNCompanyTypeStatsFilter(sensor string) ([]ASNCompanyTypeStat, error) {
	type tempStat struct {
		RemoteIP string
		ASName   string
		ASN      string
		Count    int64
	}

	ipMap := make(map[string]*tempStat)
	getOrCreate := func(ip, asn, asname string) *tempStat {
		if ip == "" {
			return nil
		}
		ip = ExtractIP(ip)
		item, exists := ipMap[ip]
		if !exists {
			item = &tempStat{
				RemoteIP: ip,
				ASN:      asn,
				ASName:   asname,
			}
			ipMap[ip] = item
		}
		if asn != "" && item.ASN == "" {
			item.ASN = asn
			item.ASName = asname
		}
		return item
	}

	var attempts []Attempt
	attQuery := DB.Model(&Attempt{})
	attQuery = ApplySensorFilter(attQuery, sensor)
	attQuery.Order("created_at desc").Limit(5000).Find(&attempts)

	for _, a := range attempts {
		item := getOrCreate(a.RemoteIP, a.ASN, a.ASName)
		if item != nil {
			item.Count++
		}
	}

	var creds []Credential
	credQuery := DB.Model(&Credential{})
	credQuery = ApplySensorFilter(credQuery, sensor)
	credQuery.Order("created_at desc").Limit(5000).Find(&creds)

	for _, c := range creds {
		item := getOrCreate(c.RemoteIP, c.ASN, c.ASName)
		if item != nil {
			item.Count++
		}
	}

	var cmds []Command
	cmdQuery := DB.Model(&Command{})
	cmdQuery = ApplySensorFilter(cmdQuery, sensor)
	cmdQuery.Order("created_at desc").Limit(5000).Find(&cmds)

	for _, cmd := range cmds {
		item := getOrCreate(cmd.RemoteIP, cmd.ASN, cmd.ASName)
		if item != nil {
			item.Count++
		}
	}

	var totalAttacks int64
	catData := make(map[string]*struct {
		attacks  int64
		ipSet    map[string]bool
		asnCount map[string]int64
	})

	categories := []string{
		"Cloud / Hosting",
		"ISP / Telecom",
		"Security Crawlers",
		"VPN / Proxy",
		"Education / Research",
		"Enterprise / Corporate",
		"Private / Local",
		"Unknown",
	}

	for _, c := range categories {
		catData[c] = &struct {
			attacks  int64
			ipSet    map[string]bool
			asnCount map[string]int64
		}{
			ipSet:    make(map[string]bool),
			asnCount: make(map[string]int64),
		}
	}

	for _, s := range ipMap {
		cat := ClassifyASNCompanyType(s.ASName, s.ASN)
		d, exists := catData[cat]
		if !exists {
			cat = "Unknown"
			d = catData["Unknown"]
		}

		d.attacks += s.Count
		d.ipSet[s.RemoteIP] = true
		totalAttacks += s.Count

		companyLabel := s.ASName
		if companyLabel == "" {
			companyLabel = s.ASN
		}
		if companyLabel != "" && companyLabel != "Unknown" {
			d.asnCount[companyLabel] += s.Count
		}
	}

	var results []ASNCompanyTypeStat
	for _, c := range categories {
		d := catData[c]
		if d.attacks == 0 && len(d.ipSet) == 0 {
			continue
		}

		pct := 0.0
		if totalAttacks > 0 {
			pct = (float64(d.attacks) / float64(totalAttacks)) * 100.0
		}

		type asnPair struct {
			Name  string
			Count int64
		}
		var pairs []asnPair
		for name, count := range d.asnCount {
			pairs = append(pairs, asnPair{Name: name, Count: count})
		}
		sort.Slice(pairs, func(i, j int) bool {
			return pairs[i].Count > pairs[j].Count
		})

		var topList []string
		for i := 0; i < len(pairs) && i < 3; i++ {
			topList = append(topList, pairs[i].Name)
		}

		results = append(results, ASNCompanyTypeStat{
			Category:    c,
			AttackCount: d.attacks,
			UniqueIPs:   int64(len(d.ipSet)),
			Percentage:  math.Round(pct*10) / 10,
			TopASNs:     topList,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].AttackCount > results[j].AttackCount
	})

	return results, nil
}

type ASNCategoryHost struct {
	RemoteIP         string    `json:"remote_ip"`
	CountryCode      string    `json:"country_code"`
	CountryName      string    `json:"country_name"`
	ASN              string    `json:"asn"`
	ASName           string    `json:"as_name"`
	ASNType          string    `json:"asn_type"`
	AttackCount      int64     `json:"attack_count"`
	CredentialsCount int64     `json:"credentials_count"`
	LastSeen         time.Time `json:"last_seen"`
}

func GetASNCategoryHostsFilter(category, sensor string) ([]ASNCategoryHost, error) {
	type rawHost struct {
		RemoteIP         string
		CountryCode      string
		CountryName      string
		ASN              string
		ASName           string
		AttackCount      int64
		CredentialsCount int64
		LastSeen         time.Time
	}

	hostMap := make(map[string]*rawHost)

	getOrCreate := func(ip, cc, cn, asn, asname string, ts time.Time) *rawHost {
		if ip == "" {
			return nil
		}
		ip = ExtractIP(ip)
		item, exists := hostMap[ip]
		if !exists {
			item = &rawHost{
				RemoteIP:    ip,
				CountryCode: cc,
				CountryName: cn,
				ASN:         asn,
				ASName:      asname,
				LastSeen:    ts,
			}
			hostMap[ip] = item
		}
		if cc != "" && item.CountryCode == "" {
			item.CountryCode = cc
			item.CountryName = cn
		}
		if asn != "" && item.ASN == "" {
			item.ASN = asn
			item.ASName = asname
		}
		if ts.After(item.LastSeen) || item.LastSeen.IsZero() {
			item.LastSeen = ts
		}
		return item
	}

	// 1. Attempts
	var attempts []Attempt
	attQuery := DB.Model(&Attempt{})
	attQuery = ApplySensorFilter(attQuery, sensor)
	attQuery.Order("created_at desc").Limit(5000).Find(&attempts)

	for _, a := range attempts {
		h := getOrCreate(a.RemoteIP, a.CountryCode, a.CountryName, a.ASN, a.ASName, a.CreatedAt)
		if h != nil {
			h.AttackCount++
		}
	}

	// 2. Credentials
	var creds []Credential
	credQuery := DB.Model(&Credential{})
	credQuery = ApplySensorFilter(credQuery, sensor)
	credQuery.Order("created_at desc").Limit(5000).Find(&creds)

	for _, c := range creds {
		h := getOrCreate(c.RemoteIP, c.CountryCode, c.CountryName, c.ASN, c.ASName, c.CreatedAt)
		if h != nil {
			h.AttackCount++
			h.CredentialsCount++
		}
	}

	// 3. Commands
	var cmds []Command
	cmdQuery := DB.Model(&Command{})
	cmdQuery = ApplySensorFilter(cmdQuery, sensor)
	cmdQuery.Order("created_at desc").Limit(5000).Find(&cmds)

	for _, cmd := range cmds {
		h := getOrCreate(cmd.RemoteIP, cmd.CountryCode, cmd.CountryName, cmd.ASN, cmd.ASName, cmd.CreatedAt)
		if h != nil {
			h.AttackCount++
		}
	}

	var results []ASNCategoryHost
	for _, h := range hostMap {
		hostCat := ClassifyASNCompanyType(h.ASName, h.ASN)
		if matchASNCategory(hostCat, category) {
			results = append(results, ASNCategoryHost{
				RemoteIP:         h.RemoteIP,
				CountryCode:      h.CountryCode,
				CountryName:      h.CountryName,
				ASN:              h.ASN,
				ASName:           h.ASName,
				ASNType:          hostCat,
				AttackCount:      h.AttackCount,
				CredentialsCount: h.CredentialsCount,
				LastSeen:         h.LastSeen,
			})
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].AttackCount > results[j].AttackCount
	})

	return results, nil
}

func ClassifyASNCompanyType(asName, asn string) string {
	name := strings.ToUpper(asName)
	asNum := strings.ToUpper(asn)
	combined := name + " " + asNum

	if name == "LOCAL MACHINE" || name == "PRIVATE LAN" || strings.Contains(name, "PRIVATE") || strings.Contains(name, "LOCAL") {
		return "Private / Local"
	}

	// 1. Security Crawlers & Scanners
	crawlerKeywords := []string{
		"SHODAN", "CENSYS", "PALO ALTO", "PALOALTO", "PANW", "STRETCHOID",
		"LEAKIX", "BINARYEDGE", "RECONNAISSANCE", "NETSYSTEMSRESEARCH",
		"SHADOWSERVER", "ONYPHE", "ALPHASTRYKE", "GREYNOISE", "ZOOMEYE",
		"CENSORNET", "SECURITY SCANNER", "SECURITY CRAWLER", "RESEARCH SCAN",
		"THREATBOOK", "PROBE", "DOUBLEDOT", "DRIFTNET", "INTERNET-MEASUREMENT",
		"PROJECT 25499", "MASSNET", "RECON", "INTERNET CRAWLER",
	}
	for _, kw := range crawlerKeywords {
		if strings.Contains(combined, kw) {
			return "Security Crawlers"
		}
	}

	// 2. Cloud / Hosting Providers (Explicit DigitalOcean matches)
	cloudKeywords := []string{
		"DIGITALOCEAN", "DIGITAL OCEAN", "DIGITAL-OCEAN", "DIGITAL_OCEAN", "AS14061", "DO-13", "DO-ASN",
		"AMAZON", "AWS", "HETZNER", "OVH", "LINODE", "AKAMAI", "MICROSOFT",
		"AZURE", "GOOGLE", "GCP", "ORACLE", "VULTR", "CONTABO", "LEASEWEB",
		"SCALEWAY", "ALIBABA", "TENCENT", "HUAWEI", "CHOOPA", "SERVERIUS",
		"M247", "HOSTINGER", "HOSTGATOR", "NAMECHEAP", "INMOTION", "FASTLY",
		"CLOUDFLARE", "FLY.IO", "ZENLAYER", "DATACAMP", "COGENT", "EQUINIX",
		"QUADRANET", "BUYVM", "HOSTSOLUTIONS", "HOSTING", "SERVER", "DATACENTER",
		"VPS", "CLOUD", "DEDICATED", "COLOCATION",
	}
	for _, kw := range cloudKeywords {
		if strings.Contains(combined, kw) {
			return "Cloud / Hosting"
		}
	}

	// 3. VPN / Proxy / Anonymizers
	vpnKeywords := []string{
		"TOR", "PROXY", "VPN", "NORD", "EXPRESSVPN", "MULLVAD", "PROTON",
		"WINDSCRIBE", "IPVANISH", "CYBERGHOST", "ANONYMOUS", "EXIT NODE",
	}
	for _, kw := range vpnKeywords {
		if strings.Contains(name, kw) {
			return "VPN / Proxy"
		}
	}

	// 4. Education / Research
	eduKeywords := []string{
		"UNIVERSITY", "COLLEGE", "UNIVERSITAS", "INSTITUTE", "RESEARCH",
		"ACADEMIC", "NORDUNET", "JANET", "GEANT", "CERNET", "EDU",
	}
	for _, kw := range eduKeywords {
		if strings.Contains(name, kw) {
			return "Education / Research"
		}
	}

	// 5. ISPs / Residential Telecom
	ispKeywords := []string{
		"COMCAST", "AT&T", "ATT-", "VERIZON", "SPECTRUM", "CHARTER", "T-MOBILE",
		"TELEKOM", "CHINA TELECOM", "CHINA UNICOM", "CHINA MOBILE", "CHINANET",
		"ORANGE", "VODAFONE", "BRITISH TELECOM", "TELSTRA", "ROGERS", "BELL",
		"SFR", "NTT", "KDDI", "SOFTBANK", "COX", "CENTURYLINK", "LUMEN",
		"FREE SAS", "TELECOM", "BROADBAND", "CABLE", "CELLULAR", "WIRELESS",
		"COMMUNICATIONS", "COMMUNICATION", "INTERNET", "TELECOMMUNICATION",
	}
	for _, kw := range ispKeywords {
		if strings.Contains(name, kw) {
			return "ISP / Telecom"
		}
	}

	// 6. Enterprise / Corporate
	govKeywords := []string{
		"BANK", "FINANCIAL", "GOVERNMENT", "MINISTRY", "DEPARTMENT", "DEFENSE",
		"MILITARY", "CORP", "INC", "LTD", "PLC", "HOLDINGS", "GROUP",
	}
	for _, kw := range govKeywords {
		if strings.Contains(name, kw) {
			return "Enterprise / Corporate"
		}
	}

	if name != "" && name != "UNKNOWN" {
		return "Enterprise / Corporate"
	}

	return "Unknown"
}

type TopProtocolByCountryStat struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Protocol    string `json:"protocol"`
	Count       int64  `json:"count"`
}

func GetTopProtocolByCountry(limit int) ([]TopProtocolByCountryStat, error) {
	return GetTopProtocolByCountryFilter(limit, "")
}

func GetTopProtocolByCountryFilter(limit int, sensor string) ([]TopProtocolByCountryStat, error) {
	var stats []TopProtocolByCountryStat
	sensorWhere, sensorArgs := SensorWhereClause(sensor, "")

	query := fmt.Sprintf(`
		SELECT country_code, country_name, protocol, count
		FROM (
			SELECT country_code, country_name, protocol, COUNT(*) as count,
			       ROW_NUMBER() OVER (PARTITION BY country_code ORDER BY COUNT(*) DESC) as rn
			FROM attempts
			WHERE country_code != '' AND country_code IS NOT NULL%s
			GROUP BY country_code, protocol
		)
		WHERE rn = 1
		ORDER BY count DESC
		LIMIT ?
	`, sensorWhere)

	args := []interface{}{}
	if len(sensorArgs) > 0 {
		args = append(args, sensorArgs[0], limit)
	} else {
		args = append(args, limit)
	}

	err := DB.Raw(query, args...).Scan(&stats).Error
	return stats, err
}

type CommandStat struct {
	Command string `json:"command"`
	Count   int64  `json:"count"`
}

func GetRecentCommands(limit int) ([]Command, error) {
	return GetRecentCommandsFilter(limit, "")
}

func GetRecentCommandsFilter(limit int, sensor string) ([]Command, error) {
	var commands []Command
	query := DB.Model(&Command{}).Order("created_at desc")
	query = ApplySensorFilter(query, sensor)
	if limit > 0 {
		query = query.Limit(limit)
	}
	err := query.Find(&commands).Error
	return commands, err
}

func GetTopCommands(limit int) ([]CommandStat, error) {
	return GetTopCommandsFilter(limit, "")
}

func GetTopCommandsFilter(limit int, sensor string) ([]CommandStat, error) {
	var stats []CommandStat
	query := DB.Model(&Command{}).Select("command, count(*) as count")
	query = ApplySensorFilter(query, sensor)
	if limit > 0 {
		query = query.Limit(limit)
	}
	err := query.Group("command").Order("count desc").Scan(&stats).Error
	return stats, err
}

type SensorInfo struct {
	SensorID    string              `json:"sensor_id"`
	DisplayName string              `json:"display_name"`
	RemoteIP    string              `json:"remote_ip"`
	EventCount  int64               `json:"event_count"`
	LastSeen    time.Time           `json:"last_seen"`
	Status      string              `json:"status"`
	CheckinTTL  int                 `json:"checkin_ttl"`
	Isolation   bool                `json:"isolation"`
	Services    []SensorServiceInfo `json:"services"`
}

func UpdateSensorDisplayName(sensorID, displayName string) error {
	if DB == nil {
		return fmt.Errorf("db not initialized")
	}
	sensorID = strings.TrimSpace(sensorID)
	if sensorID == "" {
		return fmt.Errorf("sensor_id cannot be empty")
	}
	displayName = strings.TrimSpace(displayName)

	var node SensorNode
	if err := DB.Where("sensor_id = ?", sensorID).First(&node).Error; err == nil {
		return DB.Model(&node).Update("display_name", displayName).Error
	}
	return DB.Create(&SensorNode{
		SensorID:    sensorID,
		DisplayName: displayName,
		LastSeen:    time.Now(),
		CreatedAt:   time.Now(),
	}).Error
}

func UpdateSensorServices(sensorID string, services []SensorServiceInfo) error {
	if DB == nil {
		return fmt.Errorf("db not initialized")
	}
	sensorID = strings.TrimSpace(sensorID)
	if sensorID == "" {
		return fmt.Errorf("sensor_id cannot be empty")
	}
	b, err := json.Marshal(services)
	if err != nil {
		return err
	}
	var node SensorNode
	if err := DB.Where("sensor_id = ?", sensorID).First(&node).Error; err == nil {
		return DB.Model(&node).Update("services_json", string(b)).Error
	}
	return DB.Create(&SensorNode{
		SensorID:     sensorID,
		ServicesJSON: string(b),
		LastSeen:     time.Now(),
		CreatedAt:    time.Now(),
	}).Error
}

func GetSensorNode(sensorID string) (*SensorNode, error) {
	if DB == nil {
		return nil, fmt.Errorf("db not initialized")
	}
	var node SensorNode
	err := DB.Where("sensor_id = ?", strings.TrimSpace(sensorID)).First(&node).Error
	if err != nil {
		return nil, err
	}
	return &node, nil
}

func SortSensorServices(svcs []SensorServiceInfo) {
	sort.Slice(svcs, func(i, j int) bool {
		p1, p2 := strings.ToLower(svcs[i].Protocol), strings.ToLower(svcs[j].Protocol)
		if p1 != p2 {
			return p1 < p2
		}
		return svcs[i].Port < svcs[j].Port
	})
}

func GetSensorServices(sensorID string) []SensorServiceInfo {
	if DB == nil {
		return nil
	}
	if sensorID == "" || sensorID == "all" {
		var nodes []SensorNode
		DB.Find(&nodes)
		var combined []SensorServiceInfo
		seen := make(map[string]bool)
		for _, n := range nodes {
			if n.ServicesJSON != "" {
				var svcs []SensorServiceInfo
				if err := json.Unmarshal([]byte(n.ServicesJSON), &svcs); err == nil {
					for _, s := range svcs {
						key := fmt.Sprintf("%s:%d", s.Protocol, s.Port)
						if !seen[key] {
							seen[key] = true
							combined = append(combined, s)
						}
					}
				}
			}
		}
		SortSensorServices(combined)
		return combined
	}

	var node SensorNode
	if err := DB.Where("sensor_id = ?", sensorID).First(&node).Error; err == nil {
		if node.ServicesJSON != "" {
			var svcs []SensorServiceInfo
			if err := json.Unmarshal([]byte(node.ServicesJSON), &svcs); err == nil {
				SortSensorServices(svcs)
				return svcs
			}
		}
	}
	return nil
}

func GetSensorsList() ([]SensorInfo, error) {
	if DB == nil {
		return []SensorInfo{}, nil
	}

	sensorMap := make(map[string]*SensorInfo)
	nodeMap := make(map[string]SensorNode)

	// SensorNodes
	var nodes []SensorNode
	DB.Find(&nodes)
	for _, n := range nodes {
		nodeMap[n.SensorID] = n
		var svcs []SensorServiceInfo
		if n.ServicesJSON != "" {
			_ = json.Unmarshal([]byte(n.ServicesJSON), &svcs)
		}
		status := n.Status
		if status == "" {
			status = "Active"
		}
		checkinTTL := n.CheckinTTL
		if checkinTTL <= 0 {
			checkinTTL = 15
		}
		sensorMap[n.SensorID] = &SensorInfo{
			SensorID:    n.SensorID,
			DisplayName: n.DisplayName,
			RemoteIP:    n.RemoteIP,
			EventCount:  0,
			LastSeen:    n.LastSeen,
			Status:      status,
			CheckinTTL:  checkinTTL,
			Isolation:   n.Isolation,
			Services:    svcs,
		}
	}

	// Attempts
	type SensorAgg struct {
		SensorID string
		Count    int64
		LastSeen time.Time
	}
	var attemptAggs []SensorAgg
	DB.Model(&Attempt{}).
		Select("sensor_id, count(*) as count, max(created_at) as last_seen").
		Where("sensor_id != ''").
		Group("sensor_id").
		Scan(&attemptAggs)

	for _, a := range attemptAggs {
		if s, exists := sensorMap[a.SensorID]; exists {
			s.EventCount += a.Count
			if a.LastSeen.After(s.LastSeen) {
				s.LastSeen = a.LastSeen
			}
		} else {
			dName := ""
			iso := false
			ttl := 15
			if n, ok := nodeMap[a.SensorID]; ok {
				dName = n.DisplayName
				iso = n.Isolation
				if n.CheckinTTL > 0 {
					ttl = n.CheckinTTL
				}
			}
			sensorMap[a.SensorID] = &SensorInfo{
				SensorID:    a.SensorID,
				DisplayName: dName,
				EventCount:  a.Count,
				LastSeen:    a.LastSeen,
				Status:      "Offline",
				CheckinTTL:  ttl,
				Isolation:   iso,
				Services:    []SensorServiceInfo{},
			}
		}
	}

	// Credentials
	var credAggs []SensorAgg
	DB.Model(&Credential{}).
		Select("sensor_id, count(*) as count, max(created_at) as last_seen").
		Where("sensor_id != ''").
		Group("sensor_id").
		Scan(&credAggs)

	for _, c := range credAggs {
		if s, exists := sensorMap[c.SensorID]; exists {
			s.EventCount += c.Count
			if c.LastSeen.After(s.LastSeen) {
				s.LastSeen = c.LastSeen
			}
		} else {
			dName := ""
			iso := false
			ttl := 15
			if n, ok := nodeMap[c.SensorID]; ok {
				dName = n.DisplayName
				iso = n.Isolation
				if n.CheckinTTL > 0 {
					ttl = n.CheckinTTL
				}
			}
			sensorMap[c.SensorID] = &SensorInfo{
				SensorID:    c.SensorID,
				DisplayName: dName,
				EventCount:  c.Count,
				LastSeen:    c.LastSeen,
				Status:      "Offline",
				CheckinTTL:  ttl,
				Isolation:   iso,
				Services:    []SensorServiceInfo{},
			}
		}
	}

	// Commands
	var cmdAggs []SensorAgg
	DB.Model(&Command{}).
		Select("sensor_id, count(*) as count, max(created_at) as last_seen").
		Where("sensor_id != ''").
		Group("sensor_id").
		Scan(&cmdAggs)

	for _, cmd := range cmdAggs {
		if s, exists := sensorMap[cmd.SensorID]; exists {
			s.EventCount += cmd.Count
			if cmd.LastSeen.After(s.LastSeen) {
				s.LastSeen = cmd.LastSeen
			}
		} else {
			dName := ""
			iso := false
			ttl := 15
			if n, ok := nodeMap[cmd.SensorID]; ok {
				dName = n.DisplayName
				iso = n.Isolation
				if n.CheckinTTL > 0 {
					ttl = n.CheckinTTL
				}
			}
			sensorMap[cmd.SensorID] = &SensorInfo{
				SensorID:    cmd.SensorID,
				DisplayName: dName,
				EventCount:  cmd.Count,
				LastSeen:    cmd.LastSeen,
				Status:      "Offline",
				CheckinTTL:  ttl,
				Isolation:   iso,
				Services:    []SensorServiceInfo{},
			}
		}
	}

	list := make([]SensorInfo, 0, len(sensorMap))
	now := time.Now()
	for _, s := range sensorMap {
		ttl := s.CheckinTTL
		if ttl <= 0 {
			ttl = 15
		}
		offlineThreshold := time.Duration(ttl*10) * time.Second
		if offlineThreshold < 5*time.Minute {
			offlineThreshold = 5 * time.Minute
		}
		idleThreshold := time.Duration(ttl*3) * time.Second
		if idleThreshold < 45*time.Second {
			idleThreshold = 45 * time.Second
		}

		timeSince := now.Sub(s.LastSeen)
		if timeSince > offlineThreshold {
			s.Status = "Offline"
		} else if timeSince > idleThreshold {
			s.Status = "Idle"
		} else if s.Status == "" || s.Status == "Offline" {
			s.Status = "Active"
		}
		SortSensorServices(s.Services)
		list = append(list, *s)
	}

	// Always maintain strict alphabetical ordering by SensorID
	sort.Slice(list, func(i, j int) bool {
		return strings.ToLower(list[i].SensorID) < strings.ToLower(list[j].SensorID)
	})

	return list, nil
}

var (
	loginTracker = make(map[string]time.Time)
	trackerMutex sync.Mutex
)

// AllowLogin checks if an IP is allowed to log in (rate limit of 1 successful login per 30 seconds)
func AllowLogin(remoteIP string) bool {
	ip := ExtractIP(remoteIP)
	trackerMutex.Lock()
	defer trackerMutex.Unlock()

	now := time.Now()
	if lastLogin, exists := loginTracker[ip]; exists {
		if now.Sub(lastLogin) < 30*time.Second {
			return false // Deny login (rate limited)
		}
	}
	loginTracker[ip] = now
	return true
}

// Deep Analytics & Correlations Data Structures

type CrossProtocolAttacker struct {
	RemoteIP      string    `json:"remote_ip"`
	CountryCode   string    `json:"country_code"`
	CountryName   string    `json:"country_name"`
	ASN           string    `json:"asn"`
	ASName        string    `json:"as_name"`
	Protocols     []string  `json:"protocols"`
	ProtocolCount int       `json:"protocol_count"`
	Ports         []int     `json:"ports"`
	PortCount     int       `json:"port_count"`
	TotalEvents   int64     `json:"total_events"`
	Usernames     []string  `json:"usernames"`
	Commands      []string  `json:"commands"`
	UserAgents    []string  `json:"user_agents"`
	Sensors       []string  `json:"sensors"`
	SensorCount   int       `json:"sensor_count"`
	ThreatScore   int       `json:"threat_score"`
	RiskLevel     string    `json:"risk_level"`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

type UserAgentCorrelation struct {
	UserAgent    string    `json:"user_agent"`
	RequestCount int64     `json:"request_count"`
	UniqueIPs    int       `json:"unique_ips"`
	TopIPs       []string  `json:"top_ips"`
	TopPaths     []string  `json:"top_paths"`
	LastSeen     time.Time `json:"last_seen"`
}

type WebPathCorrelation struct {
	MethodPath    string    `json:"method_path"`
	RequestCount  int64     `json:"request_count"`
	UniqueIPs     int       `json:"unique_ips"`
	TopIPs        []string  `json:"top_ips"`
	TopUserAgents []string  `json:"top_user_agents"`
	LastSeen      time.Time `json:"last_seen"`
}

type UsernameMatrix struct {
	Username   string    `json:"username"`
	TotalCount int64     `json:"total_count"`
	UniqueIPs  int       `json:"unique_ips"`
	Protocols  []string  `json:"protocols"`
	Sensors    []string  `json:"sensors"`
	LastSeen   time.Time `json:"last_seen"`
}

type AttackerHeatPoint struct {
	Lat         float64 `json:"lat"`
	Lng         float64 `json:"lng"`
	Weight      float64 `json:"weight"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	EventCount  int64   `json:"event_count"`
	IPCount     int     `json:"ip_count"`
}

type SensorPin struct {
	SensorID   string    `json:"sensor_id"`
	Status     string    `json:"status"`
	EventCount int64     `json:"event_count"`
	LastSeen   time.Time `json:"last_seen"`
	Lat        float64   `json:"lat"`
	Lng        float64   `json:"lng"`
	Protocols  []string  `json:"protocols"`
}

type CorrelationReport struct {
	CrossProtocolAttackers []CrossProtocolAttacker `json:"cross_protocol_attackers"`
	UserAgentCorrelations  []UserAgentCorrelation  `json:"user_agent_correlations"`
	WebPathCorrelations    []WebPathCorrelation    `json:"web_path_correlations"`
	UsernameMatrix         []UsernameMatrix        `json:"username_matrix"`
	Heatmap                []AttackerHeatPoint     `json:"heatmap"`
	Sensors                []SensorPin             `json:"sensors"`
}

var CountryCoordinates = map[string][2]float64{
	"US":  {37.0902, -95.7129},
	"CN":  {35.8617, 104.1954},
	"RU":  {61.5240, 105.3188},
	"BR":  {-14.2350, -51.9253},
	"DE":  {51.1657, 10.4515},
	"GB":  {55.3781, -3.4360},
	"FR":  {46.2276, 2.2137},
	"JP":  {36.2048, 138.2529},
	"IN":  {20.5937, 78.9629},
	"KR":  {35.9078, 127.7669},
	"NL":  {52.1326, 5.2913},
	"SG":  {1.3521, 103.8198},
	"UA":  {48.3794, 31.1656},
	"VN":  {14.0583, 108.2772},
	"IR":  {32.4279, 53.6880},
	"TR":  {38.9637, 35.2433},
	"CA":  {56.1304, -106.3468},
	"AU":  {-25.2744, 133.7751},
	"ES":  {40.4637, -3.7492},
	"IT":  {41.8719, 12.5674},
	"PL":  {51.9194, 19.1451},
	"RO":  {45.9432, 24.9668},
	"ID":  {-0.7893, 113.9213},
	"MX":  {23.6345, -102.5528},
	"ZA":  {-30.5595, 22.9375},
	"SE":  {60.1282, 18.6435},
	"CH":  {46.8182, 8.2275},
	"HK":  {22.3193, 114.1694},
	"TW":  {23.6978, 120.9605},
	"LCL": {37.7749, -122.4194},
	"PRV": {38.8951, -77.0364},
}

func getCountryLatMob(cc string) (float64, float64) {
	if coords, exists := CountryCoordinates[strings.ToUpper(cc)]; exists {
		return coords[0], coords[1]
	}
	if len(cc) >= 2 {
		h1 := float64(cc[0])
		h2 := float64(cc[1])
		lat := (h1 - 65.0) * 2.5
		lng := (h2 - 65.0) * 5.0 - 100.0
		return lat, lng
	}
	return 20.0, 0.0
}

func parseHTTPHeaders(rawData string) (string, string) {
	if len(rawData) == 0 {
		return "UNKNOWN", "Unknown"
	}
	if len(rawData) > 4096 {
		rawData = rawData[:4096]
	}

	// 1. Extract first non-empty line
	start := 0
	for start < len(rawData) && (rawData[start] == '\r' || rawData[start] == '\n' || rawData[start] == ' ' || rawData[start] == '\t') {
		start++
	}
	if start >= len(rawData) {
		return "UNKNOWN", "Unknown"
	}
	lineEnd := strings.IndexByte(rawData[start:], '\n')
	var firstLine string
	if lineEnd != -1 {
		firstLine = rawData[start : start+lineEnd]
	} else {
		firstLine = rawData[start:]
	}
	firstLine = strings.TrimRight(firstLine, "\r ")
	words := strings.Fields(firstLine)
	methodPath := firstLine
	if len(words) >= 2 {
		methodPath = words[0] + " " + words[1]
	}

	// 2. Extract User-Agent with zero allocations
	userAgent := "Unknown"
	target := "user-agent:"
	targetLen := len(target)
	n := len(rawData)
	for i := 0; i+targetLen <= n; i++ {
		if i == 0 || rawData[i-1] == '\n' {
			match := true
			for j := 0; j < targetLen; j++ {
				b := rawData[i+j]
				if b >= 'A' && b <= 'Z' {
					b += 32
				}
				if b != target[j] {
					match = false
					break
				}
			}
			if match {
				valStart := i + targetLen
				for valStart < n && (rawData[valStart] == ' ' || rawData[valStart] == '\t') {
					valStart++
				}
				valEnd := valStart
				for valEnd < n && rawData[valEnd] != '\r' && rawData[valEnd] != '\n' {
					valEnd++
				}
				if valEnd > valStart {
					val := strings.TrimSpace(rawData[valStart:valEnd])
					if val != "" {
						userAgent = val
					}
				}
				break
			}
		}
	}

	return methodPath, userAgent
}

func GetCorrelationReportFilter(sensor string, limit int) (CorrelationReport, error) {
	if limit <= 0 {
		limit = 100
	}

	report := CorrelationReport{
		CrossProtocolAttackers: make([]CrossProtocolAttacker, 0),
		UserAgentCorrelations:  make([]UserAgentCorrelation, 0),
		WebPathCorrelations:    make([]WebPathCorrelation, 0),
		UsernameMatrix:         make([]UsernameMatrix, 0),
		Heatmap:                make([]AttackerHeatPoint, 0),
		Sensors:                make([]SensorPin, 0),
	}

	if DB == nil {
		return report, nil
	}

	// 1. Fetch attempts, credentials, and commands (up to 10,000 recent attempts for broad cross-service correlation)
	type AttemptSummaryRow struct {
		RemoteIP    string
		Protocol    string
		Port        int
		SensorID    string
		CountryCode string
		CountryName string
		ASN         string
		ASName      string
		CreatedAt   time.Time
		RawData     string
	}
	var attempts []AttemptSummaryRow
	aQuery := DB.Model(&Attempt{}).Select("remote_ip, protocol, port, sensor_id, country_code, country_name, asn, as_name, created_at, raw_data")
	aQuery = ApplySensorFilter(aQuery, sensor)
	aQuery.Order("created_at desc").Limit(10000).Find(&attempts)

	type CredSummaryRow struct {
		RemoteIP    string
		Protocol    string
		Username    string
		SensorID    string
		CountryCode string
		CountryName string
		ASN         string
		ASName      string
		CreatedAt   time.Time
	}
	var creds []CredSummaryRow
	cQuery := DB.Model(&Credential{}).Select("remote_ip, protocol, username, sensor_id, country_code, country_name, asn, as_name, created_at")
	cQuery = ApplySensorFilter(cQuery, sensor)
	cQuery.Order("created_at desc").Limit(5000).Find(&creds)

	type CmdSummaryRow struct {
		RemoteIP    string
		Protocol    string
		Command     string
		Username    string
		SensorID    string
		CountryCode string
		CountryName string
		ASN         string
		ASName      string
		CreatedAt   time.Time
	}
	var cmds []CmdSummaryRow
	cmdQuery := DB.Model(&Command{}).Select("remote_ip, protocol, command, username, sensor_id, country_code, country_name, asn, as_name, created_at")
	cmdQuery = ApplySensorFilter(cmdQuery, sensor)
	cmdQuery.Order("created_at desc").Limit(5000).Find(&cmds)

	// Aggregation structures per IP
	type IPAgg struct {
		RemoteIP     string
		CountryCode  string
		CountryName  string
		ASN          string
		ASName       string
		Protocols    map[string]bool
		Ports        map[int]bool
		Usernames    map[string]bool
		Commands     map[string]bool
		UserAgents   map[string]bool
		Paths        map[string]bool
		Sensors      map[string]bool
		EventCount   int64
		CredCount    int64
		CmdCount     int64
		FirstSeen    time.Time
		LastSeen     time.Time
	}

	ipMap := make(map[string]*IPAgg)

	getIPAgg := func(ip, cc, cn, asn, asname string, ts time.Time) *IPAgg {
		if ip == "" {
			return nil
		}
		ip = ExtractIP(ip)
		item, exists := ipMap[ip]
		if !exists {
			item = &IPAgg{
				RemoteIP:    ip,
				CountryCode: cc,
				CountryName: cn,
				ASN:         asn,
				ASName:      asname,
				Protocols:   make(map[string]bool),
				Ports:       make(map[int]bool),
				Usernames:   make(map[string]bool),
				Commands:    make(map[string]bool),
				UserAgents:  make(map[string]bool),
				Paths:       make(map[string]bool),
				Sensors:     make(map[string]bool),
				FirstSeen:   ts,
				LastSeen:    ts,
			}
			ipMap[ip] = item
		}
		if cc != "" && item.CountryCode == "" {
			item.CountryCode = cc
			item.CountryName = cn
		}
		if asn != "" && item.ASN == "" {
			item.ASN = asn
			item.ASName = asname
		}
		if ts.Before(item.FirstSeen) || item.FirstSeen.IsZero() {
			item.FirstSeen = ts
		}
		if ts.After(item.LastSeen) {
			item.LastSeen = ts
		}
		return item
	}

	// Helper to resolve protocol to port
	protoPort := func(proto string, fallback int) int {
		if fallback > 0 {
			return fallback
		}
		switch strings.ToLower(proto) {
		case "ssh":
			return 22
		case "telnet":
			return 23
		case "web", "http":
			return 80
		case "https":
			return 443
		case "vnc":
			return 5900
		case "modbus":
			return 502
		case "s7comm":
			return 102
		default:
			return 0
		}
	}

	// Ingest attempts
	for _, a := range attempts {
		agg := getIPAgg(a.RemoteIP, a.CountryCode, a.CountryName, a.ASN, a.ASName, a.CreatedAt)
		if agg == nil {
			continue
		}
		agg.EventCount++
		if a.Protocol != "" {
			agg.Protocols[strings.ToLower(a.Protocol)] = true
		}
		p := protoPort(a.Protocol, a.Port)
		if p > 0 {
			agg.Ports[p] = true
		}
		if a.SensorID != "" {
			agg.Sensors[a.SensorID] = true
		}
		if strings.EqualFold(a.Protocol, "web") && a.RawData != "" {
			path, ua := parseHTTPHeaders(a.RawData)
			if path != "" {
				agg.Paths[path] = true
			}
			if ua != "" && ua != "Unknown" {
				agg.UserAgents[ua] = true
			}
		}
	}

	// Ingest credentials
	for _, c := range creds {
		agg := getIPAgg(c.RemoteIP, c.CountryCode, c.CountryName, c.ASN, c.ASName, c.CreatedAt)
		if agg == nil {
			continue
		}
		agg.EventCount++
		agg.CredCount++
		if c.Protocol != "" {
			agg.Protocols[strings.ToLower(c.Protocol)] = true
		}
		p := protoPort(c.Protocol, 0)
		if p > 0 {
			agg.Ports[p] = true
		}
		if c.Username != "" {
			agg.Usernames[c.Username] = true
		}
		if c.SensorID != "" {
			agg.Sensors[c.SensorID] = true
		}
	}

	// Ingest commands
	for _, cmd := range cmds {
		agg := getIPAgg(cmd.RemoteIP, cmd.CountryCode, cmd.CountryName, cmd.ASN, cmd.ASName, cmd.CreatedAt)
		if agg == nil {
			continue
		}
		agg.EventCount++
		agg.CmdCount++
		if cmd.Protocol != "" {
			agg.Protocols[strings.ToLower(cmd.Protocol)] = true
		}
		p := protoPort(cmd.Protocol, 0)
		if p > 0 {
			agg.Ports[p] = true
		}
		if cmd.Username != "" {
			agg.Usernames[cmd.Username] = true
		}
		if cmd.Command != "" {
			agg.Commands[cmd.Command] = true
		}
		if cmd.SensorID != "" {
			agg.Sensors[cmd.SensorID] = true
		}
	}

	// 2. Build Cross-Protocol & Multi-Vector High Threat Attackers
	for _, agg := range ipMap {
		protoList := make([]string, 0, len(agg.Protocols))
		for p := range agg.Protocols {
			protoList = append(protoList, p)
		}
		sort.Strings(protoList)

		portList := make([]int, 0, len(agg.Ports))
		for pt := range agg.Ports {
			portList = append(portList, pt)
		}
		sort.Ints(portList)

		userList := make([]string, 0, len(agg.Usernames))
		for u := range agg.Usernames {
			userList = append(userList, u)
		}
		cmdList := make([]string, 0, len(agg.Commands))
		for c := range agg.Commands {
			cmdList = append(cmdList, c)
		}
		uaList := make([]string, 0, len(agg.UserAgents))
		for ua := range agg.UserAgents {
			uaList = append(uaList, ua)
		}
		sensorList := make([]string, 0, len(agg.Sensors))
		for s := range agg.Sensors {
			sensorList = append(sensorList, s)
		}
		sort.Strings(sensorList)

		protoCount := len(protoList)
		portCount := len(portList)
		sensorCount := len(sensorList)

		// Threat score considers multi-protocol, multi-sensor, multi-port, creds, commands, and total events
		score := (protoCount * 25) + (sensorCount * 20) + (portCount * 15) + int(agg.CredCount*5) + int(agg.CmdCount*10) + int(agg.EventCount/10)
		if score > 100 {
			score = 100
		}

		risk := "LOW"
		if score >= 75 || protoCount >= 3 || (sensorCount >= 2 && portCount >= 3) {
			risk = "CRITICAL"
		} else if score >= 45 || protoCount >= 2 || sensorCount >= 2 || portCount >= 2 {
			risk = "HIGH"
		} else if score >= 20 {
			risk = "MEDIUM"
		}

		if protoCount >= 2 || portCount >= 2 || sensorCount >= 2 || risk == "CRITICAL" || risk == "HIGH" {
			report.CrossProtocolAttackers = append(report.CrossProtocolAttackers, CrossProtocolAttacker{
				RemoteIP:      agg.RemoteIP,
				CountryCode:   agg.CountryCode,
				CountryName:   agg.CountryName,
				ASN:           agg.ASN,
				ASName:        agg.ASName,
				Protocols:     protoList,
				ProtocolCount: protoCount,
				Ports:         portList,
				PortCount:     portCount,
				TotalEvents:   agg.EventCount,
				Usernames:     userList,
				Commands:      cmdList,
				UserAgents:    uaList,
				Sensors:       sensorList,
				SensorCount:   sensorCount,
				ThreatScore:   score,
				RiskLevel:     risk,
				FirstSeen:     agg.FirstSeen,
				LastSeen:      agg.LastSeen,
			})
		}
	}

	// 3. User-Agent and Web Path Correlation
	// Stream all web attempts across the honeypot dataset to compute complete, accurate hit counts
	type UAAgg struct {
		UserAgent string
		Count     int64
		IPs       map[string]bool
		Paths     map[string]bool
		LastSeen  time.Time
	}
	uaMap := make(map[string]*UAAgg)

	type PathAgg struct {
		Path       string
		Count      int64
		IPs        map[string]bool
		UserAgents map[string]bool
		LastSeen   time.Time
	}
	pathMap := make(map[string]*PathAgg)

	wQuery := DB.Model(&Attempt{}).Select("raw_data, remote_ip, created_at").Where("protocol IN ('web', 'http')")
	wQuery = ApplySensorFilter(wQuery, sensor)

	wRows, err := wQuery.Rows()
	if err == nil {
		defer wRows.Close()
		var rawData, remoteIP string
		var createdAt time.Time
		for wRows.Next() {
			if err := wRows.Scan(&rawData, &remoteIP, &createdAt); err != nil {
				continue
			}
			if rawData == "" {
				continue
			}
			path, ua := parseHTTPHeaders(rawData)
			if ua == "" || ua == "Unknown" {
				ua = "Mozilla/5.0 (Nmap Scan / Automated Bot)"
			}

			// UA Agg
			uItem, exists := uaMap[ua]
			if !exists {
				uItem = &UAAgg{
					UserAgent: ua,
					IPs:       make(map[string]bool),
					Paths:     make(map[string]bool),
					LastSeen:  createdAt,
				}
				uaMap[ua] = uItem
			}
			uItem.Count++
			uItem.IPs[remoteIP] = true
			if path != "" && len(uItem.Paths) < 50 {
				uItem.Paths[path] = true
			}
			if createdAt.After(uItem.LastSeen) {
				uItem.LastSeen = createdAt
			}

			// Path Agg
			if path != "" {
				pItem, exists := pathMap[path]
				if !exists {
					pItem = &PathAgg{
						Path:       path,
						IPs:        make(map[string]bool),
						UserAgents: make(map[string]bool),
						LastSeen:   createdAt,
					}
					pathMap[path] = pItem
				}
				pItem.Count++
				pItem.IPs[remoteIP] = true
				if len(pItem.UserAgents) < 50 {
					pItem.UserAgents[ua] = true
				}
				if createdAt.After(pItem.LastSeen) {
					pItem.LastSeen = createdAt
				}
			}
		}
	}

	for ua, item := range uaMap {
		maxIPs := len(item.IPs)
		if maxIPs > 50 {
			maxIPs = 50
		}
		ipList := make([]string, 0, maxIPs)
		for ip := range item.IPs {
			ipList = append(ipList, ip)
			if len(ipList) >= 50 {
				break
			}
		}
		pathList := make([]string, 0, len(item.Paths))
		for p := range item.Paths {
			pathList = append(pathList, p)
		}
		report.UserAgentCorrelations = append(report.UserAgentCorrelations, UserAgentCorrelation{
			UserAgent:    ua,
			RequestCount: item.Count,
			UniqueIPs:    len(item.IPs),
			TopIPs:       ipList,
			TopPaths:     pathList,
			LastSeen:     item.LastSeen,
		})
	}

	for path, item := range pathMap {
		maxIPs := len(item.IPs)
		if maxIPs > 50 {
			maxIPs = 50
		}
		ipList := make([]string, 0, maxIPs)
		for ip := range item.IPs {
			ipList = append(ipList, ip)
			if len(ipList) >= 50 {
				break
			}
		}
		uaList := make([]string, 0, len(item.UserAgents))
		for ua := range item.UserAgents {
			uaList = append(uaList, ua)
		}
		report.WebPathCorrelations = append(report.WebPathCorrelations, WebPathCorrelation{
			MethodPath:    path,
			RequestCount:  item.Count,
			UniqueIPs:     len(item.IPs),
			TopIPs:        ipList,
			TopUserAgents: uaList,
			LastSeen:      item.LastSeen,
		})
	}

	// 4. Targeted Usernames Correlation (Accurate SQL Aggregation Across Entire Dataset)
	type UserMatrixSQLRow struct {
		Username  string `gorm:"column:username"`
		Count     int64  `gorm:"column:total_count"`
		UniqueIPs int    `gorm:"column:unique_ips"`
		Protocols string `gorm:"column:protocols"`
		Sensors   string `gorm:"column:sensors"`
		LastSeen  string `gorm:"column:last_seen"`
	}
	var credRows []UserMatrixSQLRow
	cMatrixQuery := DB.Model(&Credential{}).
		Select("username, count(*) as total_count, count(distinct remote_ip) as unique_ips, group_concat(distinct protocol) as protocols, group_concat(distinct sensor_id) as sensors, max(created_at) as last_seen").
		Where("username != ''")
	cMatrixQuery = ApplySensorFilter(cMatrixQuery, sensor)
	cMatrixQuery.Group("username").Order("total_count DESC").Limit(limit).Scan(&credRows)

	var cmdRows []UserMatrixSQLRow
	cmdMatrixQuery := DB.Model(&Command{}).
		Select("username, count(*) as total_count, count(distinct remote_ip) as unique_ips, group_concat(distinct protocol) as protocols, group_concat(distinct sensor_id) as sensors, max(created_at) as last_seen").
		Where("username != ''")
	cmdMatrixQuery = ApplySensorFilter(cmdMatrixQuery, sensor)
	cmdMatrixQuery.Group("username").Order("total_count DESC").Limit(limit).Scan(&cmdRows)

	type UserAgg struct {
		Username  string
		Count     int64
		UniqueIPs int
		Protocols map[string]bool
		Sensors   map[string]bool
		LastSeen  time.Time
	}
	userMap := make(map[string]*UserAgg)
	for _, r := range credRows {
		u := &UserAgg{
			Username:  r.Username,
			Count:     r.Count,
			UniqueIPs: r.UniqueIPs,
			Protocols: make(map[string]bool),
			Sensors:   make(map[string]bool),
		}
		if t, err := time.Parse(time.RFC3339Nano, r.LastSeen); err == nil {
			u.LastSeen = t
		} else if t, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", r.LastSeen); err == nil {
			u.LastSeen = t
		} else if t, err := time.Parse("2006-01-02 15:04:05", r.LastSeen); err == nil {
			u.LastSeen = t
		}
		for _, p := range strings.Split(r.Protocols, ",") {
			if p != "" {
				u.Protocols[strings.ToLower(p)] = true
			}
		}
		for _, s := range strings.Split(r.Sensors, ",") {
			if s != "" {
				u.Sensors[s] = true
			}
		}
		userMap[r.Username] = u
	}

	for _, r := range cmdRows {
		u, exists := userMap[r.Username]
		if !exists {
			u = &UserAgg{
				Username:  r.Username,
				Count:     r.Count,
				UniqueIPs: r.UniqueIPs,
				Protocols: make(map[string]bool),
				Sensors:   make(map[string]bool),
			}
			userMap[r.Username] = u
		} else {
			u.Count += r.Count
			if r.UniqueIPs > u.UniqueIPs {
				u.UniqueIPs = r.UniqueIPs
			}
		}
		var t time.Time
		if pt, err := time.Parse(time.RFC3339Nano, r.LastSeen); err == nil {
			t = pt
		} else if pt, err := time.Parse("2006-01-02 15:04:05.999999999-07:00", r.LastSeen); err == nil {
			t = pt
		} else if pt, err := time.Parse("2006-01-02 15:04:05", r.LastSeen); err == nil {
			t = pt
		}
		if t.After(u.LastSeen) {
			u.LastSeen = t
		}
		for _, p := range strings.Split(r.Protocols, ",") {
			if p != "" {
				u.Protocols[strings.ToLower(p)] = true
			}
		}
		for _, s := range strings.Split(r.Sensors, ",") {
			if s != "" {
				u.Sensors[s] = true
			}
		}
	}

	for username, item := range userMap {
		pList := make([]string, 0, len(item.Protocols))
		for p := range item.Protocols {
			pList = append(pList, p)
		}
		sList := make([]string, 0, len(item.Sensors))
		for s := range item.Sensors {
			sList = append(sList, s)
		}
		report.UsernameMatrix = append(report.UsernameMatrix, UsernameMatrix{
			Username:   username,
			TotalCount: item.Count,
			UniqueIPs:  item.UniqueIPs,
			Protocols:  pList,
			Sensors:    sList,
			LastSeen:   item.LastSeen,
		})
	}

	// 5. Attacker Geographical Heatmap
	type GeoHeatAgg struct {
		CountryCode string
		CountryName string
		EventCount  int64
		IPs         map[string]bool
	}
	geoHeatMap := make(map[string]*GeoHeatAgg)

	for _, agg := range ipMap {
		cc := agg.CountryCode
		if cc == "" {
			cc = "UN"
		}
		gItem, exists := geoHeatMap[cc]
		if !exists {
			gItem = &GeoHeatAgg{
				CountryCode: cc,
				CountryName: agg.CountryName,
				IPs:         make(map[string]bool),
			}
			geoHeatMap[cc] = gItem
		}
		gItem.EventCount += agg.EventCount
		gItem.IPs[agg.RemoteIP] = true
	}

	for cc, gItem := range geoHeatMap {
		lat, lng := getCountryLatMob(cc)
		weight := float64(gItem.EventCount)
		if weight > 100 {
			weight = 100
		}
		report.Heatmap = append(report.Heatmap, AttackerHeatPoint{
			Lat:         lat,
			Lng:         lng,
			Weight:      weight,
			CountryCode: cc,
			CountryName: gItem.CountryName,
			EventCount:  gItem.EventCount,
			IPCount:     len(gItem.IPs),
		})
	}

	// 6. Deployed Sensor Location Pins
	sensorList, _ := GetSensorsList()
	if sensor != "" && sensor != "all" {
		var filteredList []SensorInfo
		for _, s := range sensorList {
			if s.SensorID == sensor || (sensor == "local" && (s.SensorID == "local" || s.SensorID == "")) {
				filteredList = append(filteredList, s)
			}
		}
		sensorList = filteredList
	}
	sensorCoords := map[string][2]float64{
		"local":          {37.7749, -122.4194}, // San Francisco
		"sensor-node-1":  {40.7128, -74.0060},  // New York
		"sensor-edge-01": {51.5074, -0.1278},   // London
		"sensor-edge-02": {35.6762, 139.6503},  // Tokyo
		"sensor-edge-03": {1.3521, 103.8198},   // Singapore
	}

	for idx, s := range sensorList {
		coords, exists := sensorCoords[s.SensorID]
		if !exists {
			lat := 20.0 + float64(idx*5)
			lng := -40.0 + float64(idx*15)
			coords = [2]float64{lat, lng}
		}
		report.Sensors = append(report.Sensors, SensorPin{
			SensorID:   s.SensorID,
			Status:     s.Status,
			EventCount: s.EventCount,
			LastSeen:   s.LastSeen,
			Lat:        coords[0],
			Lng:        coords[1],
			Protocols:  []string{"ssh", "telnet", "vnc", "web"},
		})
	}

	// 7. Deterministic sorting prioritizing recency so newly arrived attacks are immediately at the top
	for i := range report.CrossProtocolAttackers {
		sort.Strings(report.CrossProtocolAttackers[i].Protocols)
		sort.Strings(report.CrossProtocolAttackers[i].Usernames)
		sort.Strings(report.CrossProtocolAttackers[i].Commands)
		sort.Strings(report.CrossProtocolAttackers[i].UserAgents)
		sort.Strings(report.CrossProtocolAttackers[i].Sensors)
	}
	sort.Slice(report.CrossProtocolAttackers, func(i, j int) bool {
		a := report.CrossProtocolAttackers[i]
		b := report.CrossProtocolAttackers[j]

		// Prioritize recency so newly arrived attacks are immediately at the top
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}

		// Multi-Vector Diversity score: Multi-protocol (100), Multi-sensor (50), Multi-port (25)
		divA := (a.ProtocolCount * 100) + (a.SensorCount * 50) + (a.PortCount * 25)
		divB := (b.ProtocolCount * 100) + (b.SensorCount * 50) + (b.PortCount * 25)

		if divA != divB {
			return divA > divB
		}
		if a.ThreatScore != b.ThreatScore {
			return a.ThreatScore > b.ThreatScore
		}
		if a.TotalEvents != b.TotalEvents {
			return a.TotalEvents > b.TotalEvents
		}
		return a.RemoteIP < b.RemoteIP
	})

	for i := range report.UserAgentCorrelations {
		sort.Strings(report.UserAgentCorrelations[i].TopIPs)
		sort.Strings(report.UserAgentCorrelations[i].TopPaths)
	}
	sort.Slice(report.UserAgentCorrelations, func(i, j int) bool {
		a := report.UserAgentCorrelations[i]
		b := report.UserAgentCorrelations[j]
		if a.RequestCount != b.RequestCount {
			return a.RequestCount > b.RequestCount
		}
		if a.UniqueIPs != b.UniqueIPs {
			return a.UniqueIPs > b.UniqueIPs
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.UserAgent < b.UserAgent
	})

	for i := range report.WebPathCorrelations {
		sort.Strings(report.WebPathCorrelations[i].TopIPs)
		sort.Strings(report.WebPathCorrelations[i].TopUserAgents)
	}
	sort.Slice(report.WebPathCorrelations, func(i, j int) bool {
		a := report.WebPathCorrelations[i]
		b := report.WebPathCorrelations[j]
		if a.RequestCount != b.RequestCount {
			return a.RequestCount > b.RequestCount
		}
		if a.UniqueIPs != b.UniqueIPs {
			return a.UniqueIPs > b.UniqueIPs
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.MethodPath < b.MethodPath
	})

	for i := range report.UsernameMatrix {
		sort.Strings(report.UsernameMatrix[i].Protocols)
		sort.Strings(report.UsernameMatrix[i].Sensors)
	}
	sort.Slice(report.UsernameMatrix, func(i, j int) bool {
		a := report.UsernameMatrix[i]
		b := report.UsernameMatrix[j]
		if a.TotalCount != b.TotalCount {
			return a.TotalCount > b.TotalCount
		}
		if a.UniqueIPs != b.UniqueIPs {
			return a.UniqueIPs > b.UniqueIPs
		}
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.Username < b.Username
	})

	sort.Slice(report.Heatmap, func(i, j int) bool {
		if report.Heatmap[i].EventCount != report.Heatmap[j].EventCount {
			return report.Heatmap[i].EventCount > report.Heatmap[j].EventCount
		}
		return report.Heatmap[i].CountryCode < report.Heatmap[j].CountryCode
	})

	sort.Slice(report.Sensors, func(i, j int) bool {
		return report.Sensors[i].SensorID < report.Sensors[j].SensorID
	})

	if limit > 0 {
		if len(report.CrossProtocolAttackers) > limit {
			report.CrossProtocolAttackers = report.CrossProtocolAttackers[:limit]
		}
		if len(report.UserAgentCorrelations) > limit {
			report.UserAgentCorrelations = report.UserAgentCorrelations[:limit]
		}
		if len(report.WebPathCorrelations) > limit {
			report.WebPathCorrelations = report.WebPathCorrelations[:limit]
		}
		if len(report.UsernameMatrix) > limit {
			report.UsernameMatrix = report.UsernameMatrix[:limit]
		}
	}

	return report, nil
}

type ICSEvent struct {
	ID          uint      `json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	SensorID    string    `json:"sensor_id"`
	Protocol    string    `json:"protocol"`
	RemoteIP    string    `json:"remote_ip"`
	Port        int       `json:"port"`
	CountryCode string    `json:"country_code"`
	CountryName string    `json:"country_name"`
	ASN         string    `json:"asn"`
	ASName      string    `json:"as_name"`
	Command     string    `json:"command"`
	RawData     string    `json:"raw_data"`
}

type ICSAttacker struct {
	RemoteIP    string   `json:"remote_ip"`
	CountryCode string   `json:"country_code"`
	CountryName string   `json:"country_name"`
	ASN         string   `json:"asn"`
	ASName      string   `json:"as_name"`
	Count       int64    `json:"count"`
	Protocols   []string `json:"protocols"`
}

type ICSFunctionStat struct {
	FunctionCode string `json:"function_code"`
	Count        int64  `json:"count"`
}

type ICSReport struct {
	TotalAttacks      int64             `json:"total_attacks"`
	ModbusCount       int64             `json:"modbus_count"`
	S7CommCount       int64             `json:"s7comm_count"`
	UniqueAttackers   int               `json:"unique_attackers"`
	RecentEvents      []ICSEvent        `json:"recent_events"`
	TopAttackers      []ICSAttacker     `json:"top_attackers"`
	FunctionCodeStats []ICSFunctionStat `json:"function_code_stats"`
}

func FormatICSCommand(protocol, rawHex, fallbackCmd string) string {
	if fallbackCmd != "" && fallbackCmd != "-" {
		return fallbackCmd
	}
	if protocol == "modbus" && len(rawHex) >= 16 {
		fcHex := strings.ToUpper(rawHex[14:16])
		switch fcHex {
		case "01":
			return "Modbus FC=0x01 Read Coils"
		case "02":
			return "Modbus FC=0x02 Read Discrete Inputs"
		case "03":
			return "Modbus FC=0x03 Read Holding Registers"
		case "04":
			return "Modbus FC=0x04 Read Input Registers"
		case "05":
			return "Modbus FC=0x05 Write Single Coil"
		case "06":
			return "Modbus FC=0x06 Write Single Register"
		case "10":
			return "Modbus FC=0x10 Write Multiple Registers"
		case "11":
			return "Modbus FC=0x11 Report Server ID"
		case "2B":
			return "Modbus FC=0x2B Read Device Identification"
		default:
			return fmt.Sprintf("Modbus Request (FC 0x%s)", fcHex)
		}
	}
	if protocol == "s7comm" && len(rawHex) >= 8 {
		if strings.HasPrefix(strings.ToUpper(rawHex), "0300") {
			return "S7comm ISO-on-TCP (TPKT/COTP) Request"
		}
	}
	return strings.Title(protocol) + " Payload Query"
}

func GetICSReportFilter(sensor string) (*ICSReport, error) {
	report := &ICSReport{
		RecentEvents:      make([]ICSEvent, 0),
		TopAttackers:      make([]ICSAttacker, 0),
		FunctionCodeStats: make([]ICSFunctionStat, 0),
	}

	if DB == nil {
		return report, nil
	}

	// 1. Modbus / S7comm counts
	modbusQuery := DB.Model(&Attempt{}).Where("protocol = ?", "modbus")
	modbusQuery = ApplySensorFilter(modbusQuery, sensor)
	modbusQuery.Count(&report.ModbusCount)

	s7Query := DB.Model(&Attempt{}).Where("protocol = ?", "s7comm")
	s7Query = ApplySensorFilter(s7Query, sensor)
	s7Query.Count(&report.S7CommCount)

	report.TotalAttacks = report.ModbusCount + report.S7CommCount

	// 2. Recent Events (Attempt records joined with Command details)
	var attempts []Attempt
	attQuery := DB.Model(&Attempt{}).Where("protocol IN (?, ?)", "modbus", "s7comm")
	attQuery = ApplySensorFilter(attQuery, sensor)
	attQuery.Order("created_at desc").Limit(100).Find(&attempts)

	for _, a := range attempts {
		cmdText := FormatICSCommand(a.Protocol, a.RawData, "")
		var cmd Command
		if err := DB.Where("remote_ip = ? AND protocol = ?", a.RemoteIP, a.Protocol).Order("created_at desc").First(&cmd).Error; err == nil {
			if cmd.Command != "" {
				cmdText = cmd.Command
			}
		}
		report.RecentEvents = append(report.RecentEvents, ICSEvent{
			ID:          a.ID,
			CreatedAt:   a.CreatedAt,
			SensorID:    a.SensorID,
			Protocol:    a.Protocol,
			RemoteIP:    a.RemoteIP,
			Port:        a.Port,
			CountryCode: a.CountryCode,
			CountryName: a.CountryName,
			ASN:         a.ASN,
			ASName:      a.ASName,
			Command:     cmdText,
			RawData:     a.RawData,
		})
	}

	if len(attempts) == 0 {
		var commands []Command
		cmdQuery := DB.Model(&Command{}).Where("protocol IN (?, ?)", "modbus", "s7comm")
		if sensor != "" && sensor != "all" {
			cmdQuery = cmdQuery.Where("sensor_id = ?", sensor)
		}
		cmdQuery.Order("created_at desc").Limit(100).Find(&commands)

		for _, c := range commands {
			port := 502
			if c.Protocol == "s7comm" {
				port = 102
			}
			report.RecentEvents = append(report.RecentEvents, ICSEvent{
				ID:          c.ID,
				CreatedAt:   c.CreatedAt,
				SensorID:    c.SensorID,
				Protocol:    c.Protocol,
				RemoteIP:    c.RemoteIP,
				Port:        port,
				CountryCode: c.CountryCode,
				CountryName: c.CountryName,
				ASN:         c.ASN,
				ASName:      c.ASName,
				Command:     c.Command,
				RawData:     "-",
			})
		}
	}

	// 3. Top Attackers
	type HostAgg struct {
		RemoteIP    string
		CountryCode string
		CountryName string
		ASN         string
		ASName      string
		Count       int64
	}
	var topHosts []HostAgg
	hostQuery := DB.Model(&Attempt{}).
		Select("remote_ip, max(country_code) as country_code, max(country_name) as country_name, max(asn) as asn, max(as_name) as as_name, count(*) as count").
		Where("protocol IN (?, ?)", "modbus", "s7comm")
	if sensor != "" && sensor != "all" {
		hostQuery = hostQuery.Where("sensor_id = ?", sensor)
	}
	hostQuery.Group("remote_ip").Order("count desc").Limit(10).Scan(&topHosts)

	if len(topHosts) == 0 {
		cmdHostQuery := DB.Model(&Command{}).
			Select("remote_ip, max(country_code) as country_code, max(country_name) as country_name, max(asn) as asn, max(as_name) as as_name, count(*) as count").
			Where("protocol IN (?, ?)", "modbus", "s7comm")
		if sensor != "" && sensor != "all" {
			cmdHostQuery = cmdHostQuery.Where("sensor_id = ?", sensor)
		}
		cmdHostQuery.Group("remote_ip").Order("count desc").Limit(10).Scan(&topHosts)
	}

	report.UniqueAttackers = len(topHosts)
	for _, h := range topHosts {
		var protos []string
		DB.Model(&Attempt{}).
			Where("remote_ip = ? AND protocol IN (?, ?)", h.RemoteIP, "modbus", "s7comm").
			Distinct("protocol").
			Pluck("protocol", &protos)

		if len(protos) == 0 {
			DB.Model(&Command{}).
				Where("remote_ip = ? AND protocol IN (?, ?)", h.RemoteIP, "modbus", "s7comm").
				Distinct("protocol").
				Pluck("protocol", &protos)
		}

		report.TopAttackers = append(report.TopAttackers, ICSAttacker{
			RemoteIP:    h.RemoteIP,
			CountryCode: h.CountryCode,
			CountryName: h.CountryName,
			ASN:         h.ASN,
			ASName:      h.ASName,
			Count:       h.Count,
			Protocols:   protos,
		})
	}

	// 4. Function Code / Command stats
	type CmdAgg struct {
		Command string
		Count   int64
	}
	var cmdAggs []CmdAgg
	fnQuery := DB.Model(&Command{}).
		Select("command, count(*) as count").
		Where("protocol IN (?, ?)", "modbus", "s7comm")
	if sensor != "" && sensor != "all" {
		fnQuery = fnQuery.Where("sensor_id = ?", sensor)
	}
	fnQuery.Group("command").Order("count desc").Limit(10).Scan(&cmdAggs)

	for _, ca := range cmdAggs {
		report.FunctionCodeStats = append(report.FunctionCodeStats, ICSFunctionStat{
			FunctionCode: ca.Command,
			Count:        ca.Count,
		})
	}

	if len(report.FunctionCodeStats) == 0 && len(attempts) > 0 {
		fnCounts := make(map[string]int64)
		for _, a := range attempts {
			code := FormatICSCommand(a.Protocol, a.RawData, "")
			fnCounts[code]++
		}
		for code, count := range fnCounts {
			report.FunctionCodeStats = append(report.FunctionCodeStats, ICSFunctionStat{
				FunctionCode: code,
				Count:        count,
			})
		}
	}

	return report, nil
}

// TrackReconTarget records or updates an identified attack host, C2 dropper, or canary trigger IP.
// Returns the target and a boolean indicating whether it was newly inserted.
func TrackReconTarget(ip string, domain string, sourceType string, sourceContext string) (*ReconTarget, bool) {
	if DB == nil || ip == "" {
		return nil, false
	}
	ip = ExtractIP(ip)
	if ip == "" || ip == "127.0.0.1" || ip == "localhost" || ip == "::1" {
		return nil, false
	}

	var target ReconTarget
	now := time.Now()

	err := DB.Where("ip = ?", ip).First(&target).Error
	if err == nil {
		// Existing target -> increment hit count, update last seen and context
		updates := map[string]interface{}{
			"last_seen":  now,
			"hit_count":  target.HitCount + 1,
			"updated_at": now,
		}
		if (sourceType == "c2_dropper" || sourceType == "canary_hit") && target.SourceType != "canary_hit" {
			updates["source_type"] = sourceType
		}
		if sourceContext != "" && !strings.Contains(target.SourceContext, sourceContext) {
			if target.SourceContext != "" {
				updates["source_context"] = target.SourceContext + " | " + sourceContext
			} else {
				updates["source_context"] = sourceContext
			}
		}
		DB.Model(&target).Updates(updates)
		return &target, false
	}

	// New target -> resolve initial geo and assign threat score
	var countryCode, countryName, asn, asName string
	if GeoResolver != nil {
		countryCode, countryName, asn, asName, _ = GeoResolver.Resolve(ip)
	}

	initialRisk := 20
	var initialTags []string
	switch sourceType {
	case "canary_hit":
		initialRisk = 55
		initialTags = append(initialTags, "Canary Token Hit", "Deception Triggered")
	case "c2_dropper":
		initialRisk = 45
		initialTags = append(initialTags, "C2 Dropper", "Payload Host")
	default:
		initialTags = append(initialTags, "Secondary Target")
	}

	target = ReconTarget{
		IP:            ip,
		Domain:        domain,
		SourceType:    sourceType,
		SourceContext: sourceContext,
		FirstSeen:     now,
		LastSeen:      now,
		HitCount:      1,
		CountryCode:   countryCode,
		CountryName:   countryName,
		ASN:           asn,
		ASName:        asName,
		RiskScore:     initialRisk,
		Tags:          strings.Join(initialTags, ", "),
		Status:        "pending",
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := DB.Create(&target).Error; err != nil {
		return nil, false
	}
	return &target, true
}

func GetReconTargets(filter string, limit int) ([]ReconTarget, error) {
	if DB == nil {
		return []ReconTarget{}, nil
	}
	var targets []ReconTarget
	query := DB.Order("last_seen DESC, created_at DESC")
	if limit > 0 {
		query = query.Limit(limit)
	}
	if filter != "" && filter != "all" {
		query = query.Where("source_type = ? OR ip LIKE ? OR domain LIKE ? OR tags LIKE ?", filter, "%"+filter+"%", "%"+filter+"%", "%"+filter+"%")
	}
	err := query.Find(&targets).Error
	return targets, err
}

func GetReconTarget(ip string) (*ReconTarget, error) {
	if DB == nil {
		return nil, fmt.Errorf("db not initialized")
	}
	var target ReconTarget
	err := DB.Where("ip = ?", ip).First(&target).Error
	if err != nil {
		return nil, err
	}
	return &target, nil
}

func UpdateReconScan(ip string, reverseDNS string, openPorts []int, banners map[string]string, riskScore int, tags []string, status string) error {
	if DB == nil {
		return fmt.Errorf("db not initialized")
	}
	portsJSON, _ := json.Marshal(openPorts)
	bannersJSON, _ := json.Marshal(banners)

	updates := map[string]interface{}{
		"reverse_dns":  reverseDNS,
		"open_ports":   string(portsJSON),
		"banners_json": string(bannersJSON),
		"risk_score":   riskScore,
		"tags":         strings.Join(tags, ", "),
		"status":       status,
		"last_scan":    time.Now(),
		"updated_at":   time.Now(),
	}
	return DB.Model(&ReconTarget{}).Where("ip = ?", ip).Updates(updates).Error
}

func GetReconStats() (total int64, c2Droppers int64, canaryHits int64, highRisk int64) {
	if DB == nil {
		return 0, 0, 0, 0
	}
	DB.Model(&ReconTarget{}).Count(&total)
	DB.Model(&ReconTarget{}).Where("source_type = ?", "c2_dropper").Count(&c2Droppers)
	DB.Model(&ReconTarget{}).Where("source_type = ?", "canary_hit").Count(&canaryHits)
	DB.Model(&ReconTarget{}).Where("risk_score >= ?", 60).Count(&highRisk)
	return
}

// GetAttemptByID retrieves a single attempt record by its primary key ID.
func GetAttemptByID(id uint) (*Attempt, error) {
	if DB == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	var a Attempt
	err := DB.First(&a, id).Error
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// FormatHexDump formats raw payload bytes into a standard formatted hex dump (offset, hex, ASCII sidebar).
func FormatHexDump(data []byte) string {
	return hex.Dump(data)
}

// FormatRawHex formats raw payload bytes as an uninterrupted lowercase hex string.
func FormatRawHex(data []byte) string {
	return hex.EncodeToString(data)
}

// FormatASCII safely converts raw payload bytes into printable ASCII, escaping non-printable and binary bytes as \xNN.
func FormatASCII(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 {
			sb.WriteByte(b)
		} else if b == '\r' {
			sb.WriteString("\r")
		} else if b == '\n' {
			sb.WriteString("\n")
		} else if b == '\t' {
			sb.WriteString("\t")
		} else {
			sb.WriteString(fmt.Sprintf("\\x%02x", b))
		}
	}
	return sb.String()
}

// FormatBase64 encodes raw payload bytes into a standard RFC 4648 Base64 string.
func FormatBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}
