package recon

import (
	"context"
	"fmt"
	"honeygo/internal/db"
	"honeygo/internal/syslog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	autoReconMu      sync.RWMutex
	autoReconEnabled = true

	scanQueue     = make(chan string, 1000)
	scanningIPsMu sync.Mutex
	scanningIPs   = make(map[string]bool)

	urlRegex = regexp.MustCompile(`(?i)\b(?:https?|ftp|tftp)://([a-zA-Z0-9.-]+(?::[0-9]+)?)(/[^\s"'<>]*)?`)
	ipRegex  = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`)
)

type ExtractedTarget struct {
	IP            string `json:"ip"`
	Domain        string `json:"domain"`
	URL           string `json:"url"`
	SourceType    string `json:"source_type"`
	SourceContext string `json:"source_context"`
}

type ReconResult struct {
	IP          string    `json:"ip"`
	ReverseDNS  string    `json:"reverse_dns"`
	CountryCode string    `json:"country_code"`
	CountryName string    `json:"country_name"`
	ASN         string    `json:"asn"`
	ASName      string    `json:"as_name"`
	RiskScore   int       `json:"risk_score"`
	Tags        []string  `json:"tags"`
	ScanTime    time.Time `json:"scan_time"`
}

func SetAutoRecon(enabled bool) {
	autoReconMu.Lock()
	defer autoReconMu.Unlock()
	autoReconEnabled = enabled
	syslog.Info(syslog.CategorySystem, "Auto-enrichment setting updated: %v", enabled)
}

func IsAutoReconEnabled() bool {
	autoReconMu.RLock()
	defer autoReconMu.RUnlock()
	return autoReconEnabled
}

// Init initializes automatic command & canary hook listeners for recon extraction.
func Init(ctx context.Context) {
	// Hook into command recording to extract secondary payload staging IPs / C2 download links
	prevCommandHook := db.OnCommandRecorded
	db.OnCommandRecorded = func(protocol, remoteIP, username, command string) {
		if prevCommandHook != nil {
			prevCommandHook(protocol, remoteIP, username, command)
		}
		ProcessCommandForRecon(remoteIP, command)
	}

	// Backfill secondary IPs from historical commands and clean up any direct attacker records
	go BackfillSecondaryIPsFromCommands()

	go StartWorker(ctx)
}

// isPublicIP returns true if the string is a valid non-loopback, non-private IPv4 address.
func isPublicIP(ipStr string) bool {
	parsed := net.ParseIP(ipStr)
	if parsed == nil {
		return false
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsUnspecified() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return false
	}
	if ipStr == "255.255.255.255" || strings.HasPrefix(ipStr, "127.") || strings.HasPrefix(ipStr, "0.") {
		return false
	}
	return true
}

// BackfillSecondaryIPsFromCommands wipes existing c2_dropper records and re-populates ONLY
// literal IP addresses present across all historical executed commands in db.Command.
func BackfillSecondaryIPsFromCommands() {
	if db.DB == nil {
		return
	}
	// 1. Purge legacy attacker_command and c2_dropper records to ensure a clean slate from executed commands only
	db.DB.Where("source_type = ? OR source_type = ?", "attacker_command", "c2_dropper").Delete(&db.ReconTarget{})

	// 2. Extract IP addresses ONLY from the executed commands table (db.Command)
	var commands []db.Command
	if err := db.DB.Order("created_at asc").Find(&commands).Error; err == nil {
		for _, cmd := range commands {
			if cmd.Command != "" {
				cmdLower := strings.ToLower(cmd.Command)
				if strings.Contains(cmdLower, "user agent") || strings.Contains(cmdLower, "user-agent") || strings.Contains(cmdLower, "useragent") {
					continue
				}
				ProcessCommandForRecon(cmd.RemoteIP, cmd.Command)
			}
		}
	}
}

// ExtractIPsAndURLsFromCommand parses executed commands to extract literal IP addresses.
// It ONLY extracts valid public IPv4 addresses that appear directly in the executed command string.
// Commands containing User-Agent strings (web requests directed at services) are strictly ignored.
func ExtractIPsAndURLsFromCommand(cmd string) []ExtractedTarget {
	var targets []ExtractedTarget
	seen := make(map[string]bool)

	cmdTrimmed := strings.TrimSpace(cmd)
	if cmdTrimmed == "" {
		return targets
	}

	cmdLower := strings.ToLower(cmdTrimmed)
	if strings.Contains(cmdLower, "user agent") || strings.Contains(cmdLower, "user-agent") || strings.Contains(cmdLower, "useragent") {
		return targets
	}

	// Match all literal IPv4 addresses in the executed command string
	ipMatches := ipRegex.FindAllString(cmdTrimmed, -1)
	for _, rawIP := range ipMatches {
		if !isPublicIP(rawIP) {
			continue
		}
		if !seen[rawIP] {
			seen[rawIP] = true
			targets = append(targets, ExtractedTarget{
				IP:            rawIP,
				SourceType:    "c2_dropper",
				SourceContext: fmt.Sprintf("Command: %s", cmdTrimmed),
			})
		}
	}

	return targets
}

// ProcessCommandForRecon is invoked whenever a shell command is captured.
// Only literal IP addresses present in the executed command string are logged to Recon.
func ProcessCommandForRecon(remoteIP, command string) {
	cmdLower := strings.ToLower(command)
	if strings.Contains(cmdLower, "user agent") || strings.Contains(cmdLower, "user-agent") || strings.Contains(cmdLower, "useragent") {
		return
	}
	extracted := ExtractIPsAndURLsFromCommand(command)
	for _, t := range extracted {
		if t.IP != "" {
			QueueTarget(t.IP, "", t.SourceType, t.SourceContext)
		}
	}
}

// TrackCanaryHit records an IP querying or triggering canary files (e.g. .env, .aws/credentials, API tokens).
func TrackCanaryHit(remoteIP, path string) {
	if remoteIP == "" || remoteIP == "127.0.0.1" {
		return
	}
	ctx := fmt.Sprintf("Canary Token Access: %s", strings.TrimSpace(path))
	QueueTarget(remoteIP, "", "canary_hit", ctx)
}

// AddManualTarget manually registers a secondary attack infrastructure or canary hit IP.
func AddManualTarget(remoteIP, sourceType, context string) (*db.ReconTarget, error) {
	remoteIP = db.ExtractIP(remoteIP)
	if remoteIP == "" || remoteIP == "127.0.0.1" || remoteIP == "localhost" {
		return nil, fmt.Errorf("invalid or loopback IP address: %s", remoteIP)
	}

	sType := strings.TrimSpace(sourceType)
	if sType != "canary_hit" && sType != "c2_dropper" {
		if strings.Contains(strings.ToLower(sType), "canary") {
			sType = "canary_hit"
		} else {
			sType = "c2_dropper"
		}
	}

	ctx := strings.TrimSpace(context)
	if ctx == "" {
		if sType == "canary_hit" {
			ctx = "Manual Canary Token Alert"
		} else {
			ctx = "Manual Secondary Infrastructure Target"
		}
	}

	target, _ := db.TrackReconTarget(remoteIP, "", sType, ctx)
	if target != nil && IsAutoReconEnabled() {
		select {
		case scanQueue <- remoteIP:
		default:
		}
	}
	syslog.Info(syslog.CategorySystem, "Manual recon target logged: IP=%s Type=%s Context=%s", remoteIP, sType, ctx)
	return target, nil
}

// AddManualCanaryHit manually registers a canary token hit IP (e.g. triggered outside Honeygo).
func AddManualCanaryHit(remoteIP, tokenContext string) (*db.ReconTarget, error) {
	ctx := strings.TrimSpace(tokenContext)
	if ctx == "" {
		ctx = "Manual Canary Token Trigger"
	}
	return AddManualTarget(remoteIP, "canary_hit", ctx)
}

// QueueTarget tracks the target in the database and pushes to the background enrichment queue if auto-recon is enabled.
func QueueTarget(ip, domain, sourceType, sourceContext string) {
	target, isNew := db.TrackReconTarget(ip, domain, sourceType, sourceContext)
	if target == nil {
		return
	}

	if IsAutoReconEnabled() && (isNew || target.Status == "pending") {
		select {
		case scanQueue <- ip:
		default:
			// Queue full
		}
	}
}

// StartWorker runs background workers performing passive PTR and GeoIP enrichment.
func StartWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ip := <-scanQueue:
			scanningIPsMu.Lock()
			if scanningIPs[ip] {
				scanningIPsMu.Unlock()
				continue
			}
			scanningIPs[ip] = true
			scanningIPsMu.Unlock()

			// Perform passive enrichment asynchronously with recovery
			go func(targetIP string) {
				defer func() {
					scanningIPsMu.Lock()
					delete(scanningIPs, targetIP)
					scanningIPsMu.Unlock()
					if r := recover(); r != nil {
						syslog.Error(syslog.CategorySystem, "Panic during enrichment of %s: %v", targetIP, r)
					}
				}()

				_, err := ScanTarget(targetIP)
				if err != nil {
					syslog.Warn(syslog.CategorySystem, "Enrichment failed for %s: %v", targetIP, err)
				}
			}(ip)
		}
	}
}

// ScanTarget performs passive enrichment (reverse DNS PTR lookup, GeoIP resolution,
// and threat risk classification) on a target IP without active scanning.
func ScanTarget(ip string) (*ReconResult, error) {
	ip = db.ExtractIP(ip)
	if ip == "" || ip == "127.0.0.1" || ip == "localhost" {
		return nil, fmt.Errorf("invalid or loopback target IP: %s", ip)
	}

	target, err := db.GetReconTarget(ip)
	if err != nil {
		target, _ = db.TrackReconTarget(ip, "", "manual", "Manual Target Entry")
	}

	_ = db.UpdateReconScan(ip, target.ReverseDNS, nil, nil, target.RiskScore, strings.Split(target.Tags, ", "), "resolving")

	result := &ReconResult{
		IP:          ip,
		CountryCode: target.CountryCode,
		CountryName: target.CountryName,
		ASN:         target.ASN,
		ASName:      target.ASName,
		ScanTime:    time.Now(),
	}

	// 1. Passive Reverse DNS (PTR Lookup)
	if ptrs, err := net.LookupAddr(ip); err == nil && len(ptrs) > 0 {
		result.ReverseDNS = strings.TrimSuffix(ptrs[0], ".")
	}

	// 2. Re-verify GeoIP & ASN if missing
	if (result.CountryCode == "" || result.ASN == "") && db.GeoResolver != nil {
		result.CountryCode, result.CountryName, result.ASN, result.ASName, _ = db.GeoResolver.Resolve(ip)
	}

	// 3. Risk Score & Threat Tagging Calculation based on attack vectors & PTR
	result.RiskScore, result.Tags = calculateRiskAndTags(target, result)

	// 4. Update Database Record
	_ = db.UpdateReconScan(ip, result.ReverseDNS, nil, nil, result.RiskScore, result.Tags, "resolved")
	syslog.Info(syslog.CategorySystem, "Enriched attack target %s: PTR=%s, Geo=%s, Risk=%d, Tags=%v", ip, result.ReverseDNS, result.CountryCode, result.RiskScore, result.Tags)

	return result, nil
}

func calculateRiskAndTags(target *db.ReconTarget, res *ReconResult) (int, []string) {
	score := 20
	tagSet := make(map[string]bool)

	// Source Type Weighting
	switch target.SourceType {
	case "canary_hit":
		score += 45
		tagSet["Canary Token Hit"] = true
		tagSet["Deception Triggered"] = true
	case "c2_dropper":
		score += 35
		tagSet["C2 Payload Host"] = true
	default:
		tagSet["Secondary Target"] = true
	}

	// Hit Count Weighting
	if target.HitCount > 20 {
		score += 20
		tagSet["High Velocity Attack"] = true
	} else if target.HitCount > 5 {
		score += 10
		tagSet["Repeated Intruder"] = true
	}

	// Reverse DNS (PTR) checks
	if res.ReverseDNS != "" {
		rdns := strings.ToLower(res.ReverseDNS)
		if strings.Contains(rdns, "tor-exit") || strings.Contains(rdns, "tor.") {
			score += 15
			tagSet["Tor Exit Node"] = true
		}
		if strings.Contains(rdns, "vpn") || strings.Contains(rdns, "proxy") {
			score += 10
			tagSet["VPN / Proxy Host"] = true
		}
		if strings.Contains(rdns, "cloud") || strings.Contains(rdns, "vps") || strings.Contains(rdns, "hosting") || strings.Contains(rdns, "dedicated") {
			tagSet["Cloud / VPS Staging"] = true
		}
	}

	if score > 100 {
		score = 100
	}
	if score < 10 {
		score = 10
	}

	var tags []string
	for t := range tagSet {
		tags = append(tags, t)
	}

	return score, tags
}

// ScanAllPending triggers passive enrichment on all targets currently pending.
func ScanAllPending() int {
	targets, err := db.GetReconTargets("pending", 500)
	if err != nil {
		return 0
	}
	count := 0
	for _, t := range targets {
		select {
		case scanQueue <- t.IP:
			count++
		default:
		}
	}
	return count
}
