package manager

import (
	"context"
	"fmt"
	"honeygo/internal/css"
	"honeygo/internal/isolation"
	"honeygo/internal/service"
	"honeygo/internal/service/modbus"
	"honeygo/internal/service/s7comm"
	"honeygo/internal/service/ssh"
	"honeygo/internal/service/telnet"
	"honeygo/internal/service/vnc"
	"honeygo/internal/service/web"
	"honeygo/internal/syslog"
	webui "honeygo/internal/ui/web"
	"io"
	"sort"
	"strings"
	"sync"
)

type Manager struct {
	services             map[int]service.Service
	mu                   sync.RWMutex
	ctx                  context.Context
	cancel               context.CancelFunc
	Logger               io.Writer
	IsoEngine            *isolation.Engine
	DefaultWebProfile    string
	DefaultModbusProfile string
	AnalyticsSrv         *webui.WebServer
	SSLEnabled           bool
}

func NewManager() *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	mgr := &Manager{
		services:             make(map[int]service.Service),
		ctx:                  ctx,
		cancel:               cancel,
		DefaultWebProfile:    "apache",
		DefaultModbusProfile: "schneider",
		SSLEnabled:           false,
	}

	// Wire CSS service control hooks
	css.LocalStartServiceFunc = func(protocol string, port int, isolated bool, profile string, ttl int) error {
		if profile != "" {
			if protocol == "web" {
				if err := mgr.SetWebProfile(profile); err != nil {
					syslog.Warn(syslog.CategoryCSS, "Failed to set web profile '%s': %v (falling back to default)", profile, err)
				}
			} else if protocol == "modbus" {
				mgr.SetModbusProfile(profile)
			}
		}
		return mgr.StartService(protocol, port, isolated, ttl)
	}

	css.LocalStopServiceFunc = func(protocol string, port int) error {
		return mgr.StopService(protocol, port)
	}

	css.LocalIsIsolationEnabledFunc = func() bool {
		return mgr.IsoEngine != nil || isolation.IsAvailable()
	}

	css.ExecuteSensorRemoteCommandFunc = func(cmd css.SensorCommand) error {
		switch cmd.Action {
		case "start":
			if cmd.Profile != "" {
				if cmd.Protocol == "web" {
					if err := mgr.SetWebProfile(cmd.Profile); err != nil {
						syslog.Warn(syslog.CategoryCSS, "Failed to set web profile '%s': %v (falling back to default)", cmd.Profile, err)
					}
				} else if cmd.Protocol == "modbus" {
					mgr.SetModbusProfile(cmd.Profile)
				}
			}
			return mgr.StartService(cmd.Protocol, cmd.Port, cmd.Isolated, cmd.TTL)
		case "stop":
			return mgr.StopService(cmd.Protocol, cmd.Port)
		default:
			return nil
		}
	}

	css.GetRunningServicesFunc = func() []css.ServiceInfo {
		mgr.mu.RLock()
		defer mgr.mu.RUnlock()
		var res []css.ServiceInfo
		for port, s := range mgr.services {
			res = append(res, css.ServiceInfo{
				Protocol: s.Protocol(),
				Port:     port,
				Status:   s.Status(),
				Isolated: s.IsIsolated(),
			})
		}
		sort.Slice(res, func(i, j int) bool {
			p1, p2 := strings.ToLower(res[i].Protocol), strings.ToLower(res[j].Protocol)
			if p1 != p2 {
				return p1 < p2
			}
			return res[i].Port < res[j].Port
		})
		return res
	}
	return mgr
}

func (m *Manager) Ctx() context.Context {
	return m.ctx
}

func (m *Manager) SetLogger(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Logger = w
	for _, s := range m.services {
		s.SetLogger(w)
	}
	if m.AnalyticsSrv != nil {
		m.AnalyticsSrv.SetLogger(w)
	}
}

func (m *Manager) log(format string, a ...interface{}) {
	if m.Logger != nil {
		fmt.Fprintf(m.Logger, format+"\n", a...)
	}
}

func (m *Manager) AddService(s service.Service, isolated bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.services[s.Port()] = s
	if m.Logger != nil {
		s.SetLogger(m.Logger)
	}
	if isolated && m.IsoEngine != nil {
		s.EnableIsolation(m.IsoEngine)
	}
	syslog.Info(syslog.CategoryService, "Added honeypot service %s on port %d (Isolated: %v)", s.Protocol(), s.Port(), s.IsIsolated())
}

func (m *Manager) StartAll() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.services {
		if s.Status() != "Running" {
			m.log("[green]Starting %s service on port %d[white]", s.Protocol(), s.Port())
			syslog.Info(syslog.CategoryService, "Starting %s honeypot service on port %d", s.Protocol(), s.Port())
			if s.IsIsolated() && m.IsoEngine != nil {
				m.IsoEngine.StartPoolWarmer(s.Protocol())
			}
			go func(svc service.Service) {
				if err := svc.Start(m.ctx); err != nil {
					m.log("[red]Error starting service on port %d: %v[white]", svc.Port(), err)
					syslog.Error(syslog.CategoryService, "Failed to start service %s on port %d: %v", svc.Protocol(), svc.Port(), err)
				}
			}(s)
		}
	}
	return nil
}

func (m *Manager) StopAll() {
	m.cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range m.services {
		s.Stop()
		syslog.Info(syslog.CategoryService, "Stopped honeypot service %s on port %d", s.Protocol(), s.Port())
	}
	if m.AnalyticsSrv != nil {
		m.AnalyticsSrv.Stop()
		m.AnalyticsSrv = nil
		syslog.Info(syslog.CategoryWebUI, "Stopped WebUI Analytics Dashboard server")
	}
}

// SetSSL configures SSL parameters for the analytics/CSS web server
func (m *Manager) SetSSL(enabled bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.SSLEnabled = enabled
}

func (m *Manager) StartAnalytics(port int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.AnalyticsSrv != nil {
		return fmt.Errorf("analytics dashboard is already running on port %d", m.AnalyticsSrv.Port())
	}

	srv := webui.NewWebServer(port, func() int {
		status := m.GetStatus()
		activeCount := 0
		for _, s := range status {
			if s.Status == "Running" {
				activeCount++
			}
		}
		return activeCount
	}, func() []webui.ServiceStatusInfo {
		m.mu.RLock()
		defer m.mu.RUnlock()
		var res []webui.ServiceStatusInfo
		for port, s := range m.services {
			res = append(res, webui.ServiceStatusInfo{
				Protocol: s.Protocol(),
				Port:     port,
				Status:   s.Status(),
				Isolated: s.IsIsolated(),
			})
		}
		return res
	})

	if m.SSLEnabled {
		if err := srv.EnableSSL(); err != nil {
			return fmt.Errorf("failed to enable SSL on analytics server: %w", err)
		}
	}

	if err := srv.Start(); err != nil {
		return err
	}

	m.AnalyticsSrv = srv
	if m.Logger != nil {
		proto := "HTTP"
		if m.SSLEnabled {
			proto = "HTTPS"
		}
		fmt.Fprintf(m.Logger, "[green]Analytics dashboard (%s) started on port %d[white]\n", proto, port)
	}
	return nil
}

func (m *Manager) StopAnalytics() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.AnalyticsSrv == nil {
		return fmt.Errorf("analytics dashboard is not running")
	}

	err := m.AnalyticsSrv.Stop()
	m.AnalyticsSrv = nil
	return err
}

func (m *Manager) StartService(protocol string, port int, isolated bool, ttl int) error {
	m.mu.Lock()
	s, ok := m.services[port]
	if !ok {
		// Dynamically create the service based on protocol
		var newSvc service.Service
		switch protocol {
		case "ssh":
			newSvc = ssh.NewSSHService(port)
		case "telnet":
			newSvc = telnet.NewTelnetService(port)
		case "web":
			if err := web.ValidateProfile(m.DefaultWebProfile); err != nil {
				m.mu.Unlock()
				return err
			}
			newSvc = web.NewWebService(port, m.DefaultWebProfile)
		case "vnc":
			newSvc = vnc.NewVNCService(port)
		case "modbus":
			newSvc = modbus.NewModbusService(port, m.DefaultModbusProfile)
		case "s7comm":
			newSvc = s7comm.NewS7CommService(port)
		case "css":
			m.mu.Unlock()
			return m.StartAnalytics(port)
		default:
			m.mu.Unlock()
			return fmt.Errorf("unknown protocol: %s", protocol)
		}
		
		if m.Logger != nil {
			newSvc.SetLogger(m.Logger)
		}
		m.services[port] = newSvc
		s = newSvc
	}
	m.mu.Unlock()

	if s.Protocol() != protocol && !(protocol == "web" && s.Protocol() == "https") {
		return fmt.Errorf("port %d is already occupied by %s", port, s.Protocol())
	}

	if s.Status() == "Running" {
		return fmt.Errorf("service %s is already running on port %d", protocol, port)
	}

	if isolated || protocol == "modbus" || protocol == "s7comm" {
		isolated = true
		if m.IsoEngine == nil {
			engine, err := isolation.NewEngine(m.Logger)
			if err != nil {
				return fmt.Errorf("failed to initialize container isolation engine for %s: %v (ensure Podman/Docker daemon is running)", protocol, err)
			}
			m.IsoEngine = engine
			syslog.Info(syslog.CategoryIsolation, "Container isolation engine initialized lazily for %s service", protocol)
		}
		s.EnableIsolation(m.IsoEngine)
		m.IsoEngine.StartPoolWarmer(protocol)
	}

	if ttl > 0 {
		s.SetTTL(ttl)
	}

	go func() {
		if err := s.Start(m.ctx); err != nil {
			m.log("[red]Error starting service %s on port %d: %v[white]", protocol, port, err)
			syslog.Error(syslog.CategoryService, "Error starting service %s on port %d: %v", protocol, port, err)
		}
	}()
	return nil
}

func (m *Manager) StopService(protocol string, port int) error {
	m.mu.RLock()
	s, ok := m.services[port]
	m.mu.RUnlock()
	if !ok {
		return fmt.Errorf("service on port %d not found", port)
	}
	if s.Protocol() != protocol {
		return fmt.Errorf("service on port %d is %s, not %s", port, s.Protocol(), protocol)
	}
	err := s.Stop()
	if err == nil {
		m.checkAndCleanupPool(protocol)
	}
	return err
}

func (m *Manager) StopServiceByProtocol(protocol string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, s := range m.services {
		if s.Protocol() == protocol {
			s.Stop()
			count++
		}
	}
	if count > 0 {
		m.checkAndCleanupPool(protocol)
	}
	return count
}

func (m *Manager) checkAndCleanupPool(protocol string) {
	if m.IsoEngine == nil {
		return
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// Check if any other isolated instances of this protocol are still running
	stillIsolated := false
	for _, svc := range m.services {
		if svc.Protocol() == protocol && svc.Status() == "Running" && svc.IsIsolated() {
			stillIsolated = true
			break
		}
	}

	if !stillIsolated {
		m.IsoEngine.StopPoolWarmer(protocol)
	}
}

func (m *Manager) GetAvailableProtocols() []string {
	return []string{"ssh", "telnet", "web", "vnc", "modbus", "s7comm", "css"}
}

func (m *Manager) GetAvailableWebProfiles() []string {
	return web.ListAvailableProfiles()
}

func (m *Manager) SetWebProfile(profile string) error {
	if strings.TrimSpace(profile) == "" {
		profile = "apache"
	}
	if err := web.ValidateProfile(profile); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DefaultWebProfile = profile
	for _, s := range m.services {
		if s.Protocol() == "web" || s.Protocol() == "https" {
			if p, ok := s.(interface{ SetProfile(string) error }); ok {
				_ = p.SetProfile(profile)
			} else if p, ok := s.(interface{ SetProfile(string) }); ok {
				p.SetProfile(profile)
			}
		}
	}
	return nil
}

func (m *Manager) SetModbusProfile(profile string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.DefaultModbusProfile = profile
	for _, s := range m.services {
		if s.Protocol() == "modbus" {
			if p, ok := s.(interface{ SetProfile(string) }); ok {
				p.SetProfile(profile)
			}
		}
	}
}

type ServiceStatus struct {
	Protocol string
	Status   string
	Isolated bool
}

func (m *Manager) GetStatus() map[int]ServiceStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status := make(map[int]ServiceStatus)
	for port, s := range m.services {
		status[port] = ServiceStatus{
			Protocol: s.Protocol(),
			Status:   s.Status(),
			Isolated: s.IsIsolated(),
		}
	}
	return status
}
