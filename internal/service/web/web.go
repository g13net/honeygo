package web

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"honeygo/internal/db"
	"honeygo/internal/isolation"
	"honeygo/internal/misp"
	"honeygo/internal/recon"
	"honeygo/internal/syslog"
	"honeygo/internal/tlsutil"
	"honeygo/profiles"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"
)

type WebService struct {
	port       int
	profile    string
	listener   net.Listener
	logger     io.Writer
	isoEngine  *isolation.Engine
	ttl        int
	sslEnabled bool
	tlsConfig  *tls.Config
}

func NewWebService(port int, profile string) *WebService {
	if strings.TrimSpace(profile) == "" {
		profile = "apache"
	}
	return &WebService{
		port:    port,
		profile: profile,
		ttl:     300,
	}
}

func (s *WebService) log(format string, a ...interface{}) {
	if s.logger != nil {
		fmt.Fprintf(s.logger, format+"\n", a...)
	}
}

func (s *WebService) SetLogger(w io.Writer) {
	s.logger = w
}

func (s *WebService) SetProfile(profile string) error {
	if strings.TrimSpace(profile) == "" {
		profile = "apache"
	}
	if err := ValidateProfile(profile); err != nil {
		return err
	}
	s.profile = profile
	return nil
}

func (s *WebService) EnableIsolation(engine *isolation.Engine) {
	s.isoEngine = engine
}

func (s *WebService) IsIsolated() bool {
	return s.isoEngine != nil
}

func (s *WebService) SetTTL(seconds int) {
	s.ttl = seconds
}

func (s *WebService) GetTTL() int {
	return s.ttl
}

func (s *WebService) Port() int {
	return s.port
}

func (s *WebService) Protocol() string {
	if s.sslEnabled {
		return "https"
	}
	return "web"
}

// EnableSSL configures SSL/TLS encryption for the web honeypot service using certificates in ./certs/.
func (s *WebService) EnableSSL(dir ...string) error {
	certDir := "certs"
	if len(dir) > 0 && dir[0] != "" {
		certDir = dir[0]
	}
	cert, err := tlsutil.LoadCertsFromDir(certDir)
	if err != nil {
		return err
	}
	s.sslEnabled = true
	s.tlsConfig = tlsutil.NewServerTLSConfig(cert)
	return nil
}

// EnableSSLWithCert sets a pre-configured certificate (useful for unit tests).
func (s *WebService) EnableSSLWithCert(cert tls.Certificate) {
	s.sslEnabled = true
	s.tlsConfig = tlsutil.NewServerTLSConfig(cert)
}

// DisableSSL disables SSL/TLS encryption.
func (s *WebService) DisableSSL() {
	s.sslEnabled = false
	s.tlsConfig = nil
}

// IsSSLEnabled returns whether SSL/TLS encryption is enabled on the service.
func (s *WebService) IsSSLEnabled() bool {
	return s.sslEnabled
}

func (s *WebService) Status() string {
	if s.listener != nil {
		return "Running"
	}
	return "Stopped"
}

func (s *WebService) Stop() error {
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}

func (s *WebService) Start(ctx context.Context) error {
	if err := ValidateProfile(s.profile); err != nil {
		return err
	}

	ln, err := net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", s.port))
	if err != nil {
		syslog.Error(syslog.CategoryService, "Failed to start Web listener on port %d: %v", s.port, err)
		return err
	}

	if s.sslEnabled {
		if s.tlsConfig == nil {
			if err := s.EnableSSL(); err != nil {
				_ = ln.Close()
				syslog.Error(syslog.CategoryService, "Failed to enable SSL on Web listener port %d: %v", s.port, err)
				return err
			}
		}
		ln = tls.NewListener(ln, s.tlsConfig)
	}
	s.listener = ln

	proto := "Web"
	if s.sslEnabled {
		proto = "HTTPS"
	}
	s.log("[green]%s Service listening on port %d (Profile: %s)[white]", proto, s.port, s.profile)
	syslog.Info(syslog.CategoryService, "%s Service listening on port %d (Profile: %s)", proto, s.port, s.profile)

	go func() {
		for {
			l := s.listener
			if l == nil {
				return
			}
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()

	return nil
}

func (s *WebService) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return
	}
	requestStr := string(buf[:n])

	// Log HTTP connection attempt (capturing raw headers/payload for APT/vulnerability scanning research)
	db.RecordAttempt(&db.Attempt{
		Protocol: "web",
		RemoteIP: conn.RemoteAddr().String(),
		Port:     s.port,
		RawData:  requestStr,
	})


	// Parse basic auth credentials
	username, password, foundAuth := parseBasicAuth(requestStr)
	if foundAuth {
		db.RecordCredential(&db.Credential{
			Protocol: "web",
			RemoteIP: conn.RemoteAddr().String(),
			Username: username,
			Password: password,
		})
		s.log("[orange][!] Web Credential Captured (Basic Auth): %s:%s from %s[white]", username, password, db.ExtractIP(conn.RemoteAddr().String()))
	}

	// Parse POST params (for form login credentials)
	pUser, pPass, foundForm := parseFormParams(requestStr)
	if foundForm {
		db.RecordCredential(&db.Credential{
			Protocol: "web",
			RemoteIP: conn.RemoteAddr().String(),
			Username: pUser,
			Password: pPass,
		})
		s.log("[orange][!] Web Credential Captured (Form): %s:%s from %s[white]", pUser, pPass, db.ExtractIP(conn.RemoteAddr().String()))
	}

	// Trigger MISP request push
	var u, p string
	if foundAuth {
		u, p = username, password
	} else if foundForm {
		u, p = pUser, pPass
	}
	misp.PushWebRequest(conn.RemoteAddr().String(), s.port, requestStr, u, p)

	// Check if this request probed canary endpoints or AWS tokens
	path := extractPath(requestStr)
	if strings.Contains(path, ".env") || strings.Contains(path, "credentials") || strings.Contains(path, "config") || strings.Contains(requestStr, "AKIATU7L4S6WULTSTDSN") {
		recon.TrackCanaryHit(conn.RemoteAddr().String(), path)
	}

	// Send custom raw HTTP response
	responseBytes := s.buildResponse(requestStr)
	_, _ = conn.Write(responseBytes)
}

func getFirstLine(requestStr string) string {
	parts := strings.SplitN(requestStr, "\n", 2)
	if len(parts) > 0 {
		return strings.TrimSpace(parts[0])
	}
	return ""
}

func parseBasicAuth(requestStr string) (string, string, bool) {
	requestStr = strings.ReplaceAll(requestStr, "\r\n", "\n")
	lines := strings.Split(requestStr, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "authorization: basic ") {
			b64 := strings.TrimSpace(line[len("authorization: basic "):])
			decoded, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return "", "", false
			}
			creds := strings.SplitN(string(decoded), ":", 2)
			if len(creds) == 2 {
				return creds[0], creds[1], true
			}
		}
	}
	return "", "", false
}

func parseFormParams(requestStr string) (string, string, bool) {
	if !strings.HasPrefix(strings.ToUpper(requestStr), "POST ") {
		return "", "", false
	}
	
	normalized := strings.ReplaceAll(requestStr, "\r\n", "\n")
	parts := strings.SplitN(normalized, "\n\n", 2)
	if len(parts) < 2 {
		return "", "", false
	}
	body := parts[1]

	values, err := url.ParseQuery(body)
	if err != nil {
		return "", "", false
	}

	userKeys := []string{"username", "user", "j_username", "username_field", "email", "login", "admin_user", "name"}
	passKeys := []string{"password", "pass", "j_password", "password_field", "passwd", "pwd", "secret", "admin_pass"}

	var username, password string
	var hasUser, hasPass bool

	for _, k := range userKeys {
		if val := values.Get(k); val != "" {
			username = val
			hasUser = true
			break
		}
	}
	for _, k := range passKeys {
		if val := values.Get(k); val != "" {
			password = val
			hasPass = true
			break
		}
	}

	if hasUser && hasPass {
		return username, password, true
	}
	return "", "", false
}

func extractPath(requestStr string) string {
	firstLine := getFirstLine(requestStr)
	parts := strings.Fields(firstLine)
	if len(parts) >= 2 {
		target := parts[1]
		if idx := strings.Index(target, "?"); idx != -1 {
			target = target[:idx]
		}
		return strings.ToLower(target)
	}
	return "/"
}

func (s *WebService) buildResponse(requestStr string) []byte {
	isPost := strings.HasPrefix(strings.ToUpper(requestStr), "POST ")
	path := extractPath(requestStr)
	profileLower := strings.ToLower(strings.TrimSpace(s.profile))

	var template string

	// Load profile template dynamically from disk (profiles/ directory or custom file path) according to schema
	if content, err := readProfileFile(s.profile); err == nil {
		template = parseMultiPathFile(string(content), path, isPost)
	} else {
		template = getDefaultFallbackTemplate(profileLower)
	}

	// Split GET and POST template sections if the split marker exists
	splitParts := strings.Split(template, "=== POST ===")
	if len(splitParts) == 2 {
		if isPost {
			template = strings.TrimSpace(splitParts[1])
		} else {
			template = strings.TrimSpace(splitParts[0])
		}
	}

	// Dynamic RFC1123 HTTP date replacement
	nowHTTP := time.Now().UTC().Format(time.RFC1123)
	nowHTTP = strings.Replace(nowHTTP, "UTC", "GMT", 1)

	// Split headers and body supporting both CRLF and LF delimiters
	var headerPart, bodyPart string
	hasBody := false
	if strings.Contains(template, "\r\n\r\n") {
		parts := strings.SplitN(template, "\r\n\r\n", 2)
		headerPart = parts[0]
		bodyPart = parts[1]
		hasBody = true
	} else if strings.Contains(template, "\n\n") {
		parts := strings.SplitN(template, "\n\n", 2)
		headerPart = parts[0]
		bodyPart = parts[1]
		hasBody = true
	} else {
		headerPart = template
		bodyPart = ""
	}

	// Calculate body length in bytes
	bodyBytes := []byte(bodyPart)
	bodyLen := len(bodyBytes)

	// Replace placeholders
	headerPart = strings.ReplaceAll(headerPart, "[BODY_LEN]", fmt.Sprintf("%d", bodyLen))
	headerPart = strings.ReplaceAll(headerPart, "[CURRENT_DATE]", nowHTTP)
	if hasBody {
		bodyPart = strings.ReplaceAll(bodyPart, "[CURRENT_DATE]", nowHTTP)
	}

	// Standardize HTTP headers to RFC-compliant CRLF line endings
	lines := strings.Split(strings.ReplaceAll(headerPart, "\r\n", "\n"), "\n")
	standardizedHeader := strings.Join(lines, "\r\n")

	if hasBody {
		return []byte(standardizedHeader + "\r\n\r\n" + bodyPart)
	}
	return []byte(standardizedHeader + "\r\n\r\n")
}

func readProfileFile(path string) ([]byte, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, os.ErrNotExist
	}

	// Direct file path check on disk
	if content, err := os.ReadFile(trimmed); err == nil {
		return content, nil
	}

	base := strings.TrimPrefix(trimmed, "profiles/")
	base = strings.TrimPrefix(base, "/")
	base = strings.TrimSuffix(base, ".txt")

	candidates := []string{
		base,
		strings.ReplaceAll(base, "-", "_"),
		strings.ReplaceAll(base, "_", "-"),
	}

	// Alias mappings to disk & embedded profiles
	switch strings.ToLower(base) {
	case "apache":
		candidates = append(candidates, "apache_default")
	case "iis":
		candidates = append(candidates, "iis_default")
	case "pizza", "pizzarea", "pizza_shop", "pizzashop":
		candidates = append(candidates, "pizzashop")
	case "aws", "canary", "aws-canary", "aws_canary":
		candidates = append(candidates, "aws_canary")
	case "generic", "generic_form", "generic-form":
		candidates = append(candidates, "generic_form")
	case "jenkins", "jenkins_login", "jenkins-login":
		candidates = append(candidates, "jenkins_login")
	case "cisco":
		candidates = append(candidates, "cisco")
	case "nginx":
		candidates = append(candidates, "nginx")
	case "tomcat":
		candidates = append(candidates, "tomcat")
	case "login-portal", "login_portal", "login":
		candidates = append(candidates, "login-portal", "login_portal")
	case "router-admin", "router_admin", "router":
		candidates = append(candidates, "router-admin", "router_admin")
	}

	// 1. Try disk paths first (allows live user modifications and custom profiles on disk)
	prefixes := []string{"", "profiles/", "../profiles/", "../../profiles/", "../../../profiles/"}
	for _, p := range prefixes {
		for _, c := range candidates {
			if content, err := os.ReadFile(p + c + ".txt"); err == nil {
				return content, nil
			}
			if content, err := os.ReadFile(p + c); err == nil {
				return content, nil
			}
		}
	}

	for _, up := range []string{"../", "../../", "../../../"} {
		if content, err := os.ReadFile(up + trimmed); err == nil {
			return content, nil
		}
	}

	// 2. Try embedded profiles FS (guarantees standalone sensor binary functions everywhere)
	for _, c := range candidates {
		if content, err := profiles.FS.ReadFile(c + ".txt"); err == nil {
			return content, nil
		}
		if content, err := profiles.FS.ReadFile(c); err == nil {
			return content, nil
		}
	}

	return nil, os.ErrNotExist
}

// ListAvailableProfiles scans the profiles directory and returns all available web profile names
func ListAvailableProfiles() []string {
	seen := make(map[string]bool)
	var list []string

	addProfile := func(name string) {
		name = strings.TrimSpace(name)
		if name != "" && !seen[name] {
			seen[name] = true
			list = append(list, name)
		}
	}

	// Always include standard built-in profile aliases
	addProfile("apache")
	addProfile("iis")
	addProfile("cisco")
	addProfile("aws-canary")
	addProfile("pizzashop")
	addProfile("nginx")
	addProfile("tomcat")
	addProfile("login-portal")
	addProfile("router-admin")
	addProfile("generic_form")
	addProfile("jenkins_login")

	// Read embedded profiles FS
	if entries, err := profiles.FS.ReadDir("."); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".txt") {
				base := strings.TrimSuffix(e.Name(), ".txt")
				addProfile(base)
			}
		}
	}

	// Scan profiles directory on disk
	prefixes := []string{"profiles", "../profiles", "../../profiles", "../../../profiles"}
	for _, dir := range prefixes {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".txt") {
				base := strings.TrimSuffix(name, ".txt")
				addProfile(base)
			}
		}
		break // Found valid profiles directory
	}

	return list
}

// ValidateProfile checks whether a given profile name or file path is valid and exists
func ValidateProfile(profile string) error {
	trimmed := strings.TrimSpace(profile)
	if trimmed == "" {
		return fmt.Errorf("web profile cannot be empty")
	}

	base := strings.TrimPrefix(trimmed, "profiles/")
	base = strings.TrimPrefix(base, "/")
	base = strings.TrimSuffix(base, ".txt")
	baseLower := strings.ToLower(base)

	switch baseLower {
	case "apache", "apache_default", "iis", "iis_default", "cisco":
		return nil
	case "aws-canary", "aws", "canary", "aws_canary":
		return nil
	case "pizzashop", "pizza", "pizzarea", "pizza_shop":
		return nil
	case "generic", "generic_form", "generic-form":
		return nil
	case "jenkins", "jenkins_login", "jenkins-login":
		return nil
	case "nginx", "tomcat", "login-portal", "login_portal", "router-admin", "router_admin":
		return nil
	}

	if _, err := readProfileFile(trimmed); err == nil {
		return nil
	}

	return fmt.Errorf("web profile '%s' not found (available: %s, or profile files in profiles/)", profile, strings.Join(ListAvailableProfiles(), ", "))
}

// ProfileExists returns true if the profile is valid and exists
func ProfileExists(profile string) bool {
	return ValidateProfile(profile) == nil
}

type pathSection struct {
	pattern  string
	template string
}

func parseMultiPathFile(content string, reqPath string, isPost bool) string {
	// If file contains "=== PATH:", split into path sections
	if strings.Contains(content, "=== PATH:") {
		sections := strings.Split(content, "=== PATH:")
		var routes []pathSection
		var defaultTemplate string

		reqPathClean := strings.ToLower(strings.TrimSpace(reqPath))

		for _, sec := range sections {
			sec = strings.TrimSpace(sec)
			if sec == "" {
				continue
			}
			parts := strings.SplitN(sec, "===", 2)
			if len(parts) != 2 {
				continue
			}
			pattern := strings.ToLower(strings.TrimSpace(parts[0]))
			tpl := strings.TrimSpace(parts[1])

			if pattern == "/" || pattern == "default" || pattern == "*" {
				defaultTemplate = tpl
			}

			routes = append(routes, pathSection{pattern: pattern, template: tpl})
		}

		// 1. Exact match (e.g. "/v1/models" == "/v1/models" or trailing slash equivalence)
		for _, r := range routes {
			if reqPathClean == r.pattern || strings.TrimSuffix(reqPathClean, "/") == strings.TrimSuffix(r.pattern, "/") {
				return r.template
			}
		}

		// 2. Prefix / wildcard match for subpaths (e.g. "/api/*", "/static/")
		for _, r := range routes {
			if strings.HasSuffix(r.pattern, "/*") {
				prefix := strings.TrimSuffix(r.pattern, "*")
				if strings.HasPrefix(reqPathClean, prefix) {
					return r.template
				}
			} else if strings.HasSuffix(r.pattern, "/") && r.pattern != "/" {
				if strings.HasPrefix(reqPathClean, r.pattern) {
					return r.template
				}
			}
		}

		// 3. Default template fallback (e.g., "/" or "default" or "*")
		if defaultTemplate != "" {
			return defaultTemplate
		}

		// 4. If no default template defined, return the first defined route
		if len(routes) > 0 {
			return routes[0].template
		}
	}

	return content
}

// getDefaultFallbackTemplate returns a minimal generic fallback response if no profile file is available on disk or embedded
func getDefaultFallbackTemplate(profileLower string) string {
	base := strings.TrimPrefix(profileLower, "profiles/")
	base = strings.TrimPrefix(base, "/")
	base = strings.TrimSuffix(base, ".txt")

	switch strings.ToLower(base) {
	case "iis", "iis_default":
		return "HTTP/1.1 200 OK\r\nContent-Length: [BODY_LEN]\r\nContent-Type: text/html\r\nServer: Microsoft-IIS/10.0\r\nDate: [CURRENT_DATE]\r\nConnection: close\r\n\r\n<!DOCTYPE html><html><head><title>IIS Windows Server</title></head><body><h1>Welcome to IIS 10</h1></body></html>\n"
	case "cisco":
		return "HTTP/1.1 401 Unauthorized\r\nDate: [CURRENT_DATE]\r\nServer: cisco-IOS\r\nAccept-Ranges: none\r\nWWW-Authenticate: Basic realm=\"Cisco Switch\"\r\nContent-Length: [BODY_LEN]\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><head><title>401 Unauthorized</title></head><body><h1>401 Unauthorized</h1><p>Authorization Required.</p></body></html>\n"
	case "nginx":
		return "HTTP/1.1 200 OK\r\nDate: [CURRENT_DATE]\r\nServer: nginx/1.18.0 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: [BODY_LEN]\r\nConnection: close\r\n\r\n<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body><h1>Welcome to nginx!</h1></body></html>\n"
	case "tomcat":
		return "HTTP/1.1 200 OK\r\nDate: [CURRENT_DATE]\r\nServer: Apache-Coyote/1.1\r\nContent-Type: text/html;charset=UTF-8\r\nContent-Length: [BODY_LEN]\r\nConnection: close\r\n\r\n<!DOCTYPE html><html><head><title>Apache Tomcat</title></head><body><h1>Apache Tomcat</h1></body></html>\n"
	case "router-admin", "router_admin":
		return "HTTP/1.1 401 Unauthorized\r\nDate: [CURRENT_DATE]\r\nServer: RouterOS v6.48\r\nWWW-Authenticate: Basic realm=\"Router Gateway Configuration\"\r\nContent-Type: text/html\r\nContent-Length: [BODY_LEN]\r\nConnection: close\r\n\r\n<html><head><title>401 Authorization Required</title></head><body><h1>401 Authorization Required</h1></body></html>\n"
	case "login-portal", "login_portal":
		return "HTTP/1.1 200 OK\r\nDate: [CURRENT_DATE]\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: [BODY_LEN]\r\nConnection: close\r\n\r\n<!DOCTYPE html><html><head><title>Employee Portal - Login</title></head><body><h1>Single Sign-On</h1></body></html>\n"
	case "aws-canary", "aws", "canary", "aws_canary":
		return "HTTP/1.1 200 OK\r\nDate: [CURRENT_DATE]\r\nServer: AmazonS3\r\nContent-Type: application/json\r\nContent-Length: [BODY_LEN]\r\nConnection: close\r\n\r\n{\"status\":\"healthy\",\"service\":\"aws-storage-canary\",\"env\":\"production\",\"aws_access_key_id\":\"AKIATU7L4S6WULTSTDSN\"}\n"
	case "pizzashop", "pizza", "pizzarea", "pizza_shop":
		return "HTTP/1.1 200 OK\r\nDate: [CURRENT_DATE]\r\nServer: Apache/2.4.41 (Unix)\r\nContent-Length: [BODY_LEN]\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html><html><head><title>🍕 LUIGI & GUIDO'S EXTREME PIZZA 3000 🍕</title></head><body><h1>🍕 LUIGI & GUIDO'S EXTREME PIZZA 3000 🍕</h1></body></html>\n"
	case "apache", "apache_default":
		fallthrough
	default:
		return "HTTP/1.1 200 OK\r\nDate: [CURRENT_DATE]\r\nServer: Apache/2.4.41 (Unix)\r\nContent-Length: [BODY_LEN]\r\nConnection: close\r\nContent-Type: text/html\r\n\r\n<html><body><h1>It works!</h1></body></html>\n"
	}
}
