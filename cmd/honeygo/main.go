package main

import (
	"context"
	"flag"
	"fmt"
	"honeygo/internal/alerting"
	"honeygo/internal/css"
	"honeygo/internal/db"
	"honeygo/internal/isolation"
	"honeygo/internal/manager"
	"honeygo/internal/misp"
	"honeygo/internal/recon"
	"honeygo/internal/service/modbus"
	"honeygo/internal/service/s7comm"
	"honeygo/internal/service/ssh"
	"honeygo/internal/service/telnet"
	"honeygo/internal/service/vnc"
	"honeygo/internal/service/web"
	"honeygo/internal/syslog"
	"honeygo/internal/tlsutil"
	"honeygo/internal/ui"
	"log"
	"os"
	"strings"

	"golang.org/x/term"
)

type Config struct {
	IsolationEnabled bool
	DBPath           string
	ClearDB          bool

	SSHEnabled bool
	SSHPort    int

	TelnetEnabled bool
	TelnetPort    int

	WebEnabled bool
	WebPort    int
	WebProfile string

	VNCEnabled bool
	VNCPort    int

	ModbusEnabled bool
	ModbusPort    int
	ModbusProfile string

	S7commEnabled bool
	S7commPort    int

	MISPURL        string
	MISPKey        string
	MISPSkipVerify bool

	AnalyticsEnabled bool
	AnalyticsPort    int

	TelegramToken  string
	TelegramChatID string

	CSSServer     bool
	CSSPort       int
	CSSURL        string
	CSSToken      string
	CSSAuth       bool
	SensorID      string
	SensorTTL     int
	CSSSkipVerify bool

	SSLEnabled bool
	WebSSL     bool

	CartoKey string

	InfoEnabled bool

	ShowVersion bool
}

func parseCLI(args []string) (*Config, error) {
	// Enforce strict traditional Unix syntax:
	// Single dash is ONLY allowed for single-character options (-h, -v, -k).
	// Full word options (e.g. --ssh, --help, --web) MUST use double dashes '--'.
	for _, arg := range args {
		if arg == "--" {
			break
		}
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			flagBody := strings.TrimPrefix(arg, "-")
			if idx := strings.Index(flagBody, "="); idx != -1 {
				flagBody = flagBody[:idx]
			}
			if flagBody != "h" && flagBody != "v" && flagBody != "k" {
				return nil, fmt.Errorf("invalid single-dash flag '%s': full word options must use double dashes '--' (e.g. --%s)", arg, flagBody)
			}
		}
	}

	cfg := &Config{}
	fs := flag.NewFlagSet("honeygo", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Print(ui.FormatCLIHelp())
	}

	versionFlag := fs.Bool("version", false, "Print version information and exit")
	vFlag := fs.Bool("v", false, "Print version information and exit")
	hFlag := fs.Bool("h", false, "Show help and exit")
	helpFlag := fs.Bool("help", false, "Show help and exit")

	fs.BoolVar(&cfg.IsolationEnabled, "isolation", false, "Enable container-based isolation")
	fs.StringVar(&cfg.DBPath, "db", "honeygo.db", "Path to SQLite database")
	fs.BoolVar(&cfg.ClearDB, "clear-db", false, "Clear the database on startup")

	fs.BoolVar(&cfg.SSHEnabled, "ssh", false, "Enable SSH honeypot")
	fs.IntVar(&cfg.SSHPort, "ssh-port", 2222, "SSH honeypot port")

	fs.BoolVar(&cfg.TelnetEnabled, "telnet", false, "Enable Telnet honeypot")
	fs.IntVar(&cfg.TelnetPort, "telnet-port", 2323, "Telnet honeypot port")

	fs.BoolVar(&cfg.WebEnabled, "web", false, "Enable Web honeypot")
	fs.IntVar(&cfg.WebPort, "web-port", 8080, "Web honeypot port")
	fs.StringVar(&cfg.WebProfile, "web-profile", "apache", "Web profile")

	fs.BoolVar(&cfg.VNCEnabled, "vnc", false, "Enable VNC honeypot")
	fs.IntVar(&cfg.VNCPort, "vnc-port", 5900, "VNC honeypot port")

	fs.BoolVar(&cfg.ModbusEnabled, "modbus", false, "Enable Modbus TCP PLC honeypot")
	fs.IntVar(&cfg.ModbusPort, "modbus-port", 502, "Modbus TCP PLC honeypot port")
	fs.StringVar(&cfg.ModbusProfile, "modbus-profile", "schneider", "Modbus PLC profile")

	fs.BoolVar(&cfg.S7commEnabled, "s7comm", false, "Enable Siemens S7comm PLC honeypot")
	fs.IntVar(&cfg.S7commPort, "s7comm-port", 102, "Siemens S7comm PLC honeypot port")

	fs.StringVar(&cfg.MISPURL, "misp-url", "", "MISP server URL")
	fs.StringVar(&cfg.MISPKey, "misp-key", "", "MISP API Auth Key")
	fs.BoolVar(&cfg.MISPSkipVerify, "misp-skip-verify", false, "Skip SSL/TLS verification for MISP")

	fs.BoolVar(&cfg.AnalyticsEnabled, "analytics", false, "Enable Web Analytics Dashboard server")
	fs.IntVar(&cfg.AnalyticsPort, "analytics-port", 8090, "Web Analytics Dashboard server port")

	fs.StringVar(&cfg.TelegramToken, "telegram-token", "", "Telegram Bot API Token")
	fs.StringVar(&cfg.TelegramChatID, "telegram-chat-id", "", "Telegram Chat ID")

	fs.BoolVar(&cfg.CSSServer, "css-server", false, "Launch in Central Storage Server mode")
	fs.IntVar(&cfg.CSSPort, "css-port", 8090, "Port for Central Storage Server")
	fs.StringVar(&cfg.CSSURL, "css-url", "", "URL of Central Storage Server")
	fs.StringVar(&cfg.CSSToken, "css-token", "", "Authentication token for CSS")
	fs.BoolVar(&cfg.CSSAuth, "css-auth", false, "Enable token authentication on CSS")
	fs.StringVar(&cfg.SensorID, "sensor-id", "", "Unique identifier for this sensor")
	fs.IntVar(&cfg.SensorTTL, "sensor-ttl", 15, "Checkin TTL heartbeat interval in seconds for sensor (default 15)")
	fs.IntVar(&cfg.SensorTTL, "sensor-checkin-ttl", 15, "Checkin TTL heartbeat interval in seconds for sensor (default 15)")
	fs.IntVar(&cfg.SensorTTL, "checkin-ttl", 15, "Checkin TTL heartbeat interval in seconds for sensor (default 15)")
	kFlag := fs.Bool("k", false, "Ignore self-signed SSL/TLS certificates when connecting to CSS")
	fs.BoolVar(&cfg.CSSSkipVerify, "insecure", false, "Ignore self-signed SSL/TLS certificates when connecting to CSS (alias for -k)")
	fs.BoolVar(&cfg.CSSSkipVerify, "skip-verify", false, "Ignore self-signed SSL/TLS certificates when connecting to CSS")
	fs.BoolVar(&cfg.CSSSkipVerify, "css-skip-verify", false, "Ignore self-signed SSL/TLS certificates when connecting to CSS")

	fs.BoolVar(&cfg.SSLEnabled, "ssl", false, "Enable SSL/TLS encryption for CSS server and WebUI (requires ./certs/server.crt and ./certs/server.key)")
	fs.BoolVar(&cfg.WebSSL, "web-ssl", false, "Enable SSL/TLS encryption for Web honeypot service (requires ./certs/server.crt and ./certs/server.key)")

	fs.StringVar(&cfg.CartoKey, "carto-key", "", "API key for CARTO threat heatmap basemaps")
	fs.StringVar(&cfg.CartoKey, "cartomap-key", "", "API key for CARTO threat heatmap basemaps")

	fs.BoolVar(&cfg.InfoEnabled, "info", false, "Enable live streaming of informational messages (connected sensors, events, errors)")
	fs.BoolVar(&cfg.InfoEnabled, "verbose", false, "Enable live streaming of informational messages (alias for --info)")

	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil, err
		}
		return nil, err
	}

	if *kFlag {
		cfg.CSSSkipVerify = true
	}

	if *hFlag || *helpFlag {
		fs.Usage()
		return nil, flag.ErrHelp
	}

	if *versionFlag || *vFlag {
		cfg.ShowVersion = true
		return cfg, nil
	}

	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected argument '%s'", fs.Arg(0))
	}

	return cfg, nil
}

func main() {
	cfg, err := parseCLI(os.Args[1:])
	if err != nil {
		if err == flag.ErrHelp {
			os.Exit(0)
		}
		fmt.Printf("Error: %v\n\n", err)
		fmt.Print(ui.FormatCLIHelp())
		os.Exit(1)
	}

	if cfg.ShowVersion {
		fmt.Printf("Honeygo %s\n", ui.Version)
		return
	}

	ui.PrintBanner()

	logFile := "honeygo.log"
	if err := syslog.Init(logFile); err != nil {
		log.Printf("Warning: Failed to initialize syslog file: %v", err)
	}
	syslog.SetInfoLogging(cfg.InfoEnabled)
	syslog.Info(syslog.CategorySystem, "Honeygo %s initialized (Isolation: %v, DB: %s)", ui.Version, cfg.IsolationEnabled, cfg.DBPath)

	// Configure alerting
	alerting.Token = cfg.TelegramToken
	alerting.ChatID = cfg.TelegramChatID

	if err := db.InitDB(); err != nil {
		syslog.Error(syslog.CategoryDB, "Failed to initialize database: %v", err)
		log.Fatalf("Failed to initialize database: %v", err)
	}

	if cfg.ClearDB {
		if err := db.ClearDB(); err != nil {
			syslog.Warn(syslog.CategoryDB, "Failed to clear database: %v", err)
			log.Printf("Warning: Failed to clear database: %v", err)
		} else {
			syslog.Info(syslog.CategoryDB, "Database cleared successfully")
			fmt.Println("Database cleared successfully.")
		}
	}

	fmt.Printf("Database initialized at %s (Isolation: %v)\n", cfg.DBPath, cfg.IsolationEnabled)

	// Configure CARTO Map API key if provided via flag or environment
	if cfg.CartoKey != "" {
		css.SetCartoAPIKey(cfg.CartoKey)
	} else if envKey := os.Getenv("CARTO_API_KEY"); envKey != "" {
		css.SetCartoAPIKey(envKey)
	} else if envKey := os.Getenv("CARTOMAP_API_KEY"); envKey != "" {
		css.SetCartoAPIKey(envKey)
	}

	// Configure Central Storage Server / Sensor Mode
	if cfg.SensorTTL > 0 {
		css.SetSensorCheckinTTL(cfg.SensorTTL)
	}
	if cfg.CSSSkipVerify {
		css.SetSensorSkipVerify(true)
	}

	mgr := manager.NewManager()
	mgr.SetSSL(cfg.SSLEnabled)
	if cfg.WebProfile != "" {
		if err := mgr.SetWebProfile(cfg.WebProfile); err != nil {
			log.Fatalf("Invalid --web-profile: %v", err)
		}
	}
	mgr.DefaultModbusProfile = cfg.ModbusProfile

	if cfg.CSSURL != "" {
		tokenAuth := cfg.CSSToken
		if err := css.ConnectSensorWithVerify(cfg.CSSURL, tokenAuth, cfg.SensorID, cfg.SensorTTL, cfg.CSSSkipVerify); err != nil {
			log.Printf("Warning: Failed to connect to Central Storage Server at %s: %v (operating in standalone mode)", cfg.CSSURL, err)
			fmt.Printf("[!] Failed to connect to Central Storage Server at %s: %v (operating in standalone mode)\n", cfg.CSSURL, err)
		} else {
			verifyMsg := ""
			if cfg.CSSSkipVerify {
				verifyMsg = ", self-signed SSL certs accepted"
			}
			fmt.Printf("Connected to Central Storage Server at %s as sensor '%s' (TTL: %ds%s, server acknowledged, local logs, MISP, and Telegram disabled)\n", cfg.CSSURL, css.GetSensorID(), css.GetSensorCheckinTTL(), verifyMsg)
		}
	}

	tokenAuthActive := cfg.CSSAuth || (cfg.CSSToken != "")
	if cfg.CSSServer {
		css.SetServerConfig(true, cfg.CSSPort, tokenAuthActive, cfg.CSSToken, cfg.SSLEnabled)
	}

	// Initialize MISP Client
	misp.Init(cfg.MISPURL, cfg.MISPKey, cfg.MISPSkipVerify, os.Stdout)

	// Initialize Reconnaissance Engine & Command/Canary Extraction Hooks
	recon.Init(context.Background())

	// Start Web Analytics / CSS Server if requested via --analytics or --css-server
	srvPort := cfg.AnalyticsPort
	if cfg.CSSServer {
		srvPort = cfg.CSSPort
	}
	if cfg.AnalyticsEnabled || cfg.CSSServer {
		if cfg.SSLEnabled {
			if _, err := tlsutil.LoadCertsFromDir("certs"); err != nil {
				log.Fatalf("Error: %v\nPlease place your SSL certificate and private key in ./certs/ (e.g. ./certs/server.crt and ./certs/server.key)", err)
			}
		}
		if err := mgr.StartAnalytics(srvPort); err != nil {
			log.Fatalf("Error starting CSS / analytics server on port %d: %v", srvPort, err)
		} else {
			css.SetServerConfig(true, srvPort, tokenAuthActive, cfg.CSSToken, cfg.SSLEnabled)
		}
	}

	if cfg.IsolationEnabled {
		engine, err := isolation.NewEngine(os.Stdout) // Temporary logger until shell is ready
		if err != nil {
			log.Fatalf("Failed to initialize isolation engine: %v", err)
		}
		mgr.IsoEngine = engine
	}
	
	// Add services based on flags
	if cfg.SSHEnabled {
		mgr.AddService(ssh.NewSSHService(cfg.SSHPort), cfg.IsolationEnabled)
	}
	if cfg.TelnetEnabled {
		mgr.AddService(telnet.NewTelnetService(cfg.TelnetPort), cfg.IsolationEnabled)
	}
	if cfg.WebEnabled {
		webSvc := web.NewWebService(cfg.WebPort, cfg.WebProfile)
		if cfg.WebSSL {
			if err := webSvc.EnableSSL(); err != nil {
				log.Fatalf("Failed to enable SSL on Web honeypot service: %v\nPlease place your SSL certificate and private key in ./certs/ (e.g. ./certs/server.crt and ./certs/server.key)", err)
			}
		}
		mgr.AddService(webSvc, cfg.IsolationEnabled)
	}
	if cfg.VNCEnabled {
		mgr.AddService(vnc.NewVNCService(cfg.VNCPort), cfg.IsolationEnabled)
	}
	if cfg.ModbusEnabled {
		if !cfg.IsolationEnabled {
			log.Fatalf("Error: Modbus PLC service requires container isolation (must specify --isolation)")
		}
		mgr.AddService(modbus.NewModbusService(cfg.ModbusPort, cfg.ModbusProfile), cfg.IsolationEnabled)
	}
	if cfg.S7commEnabled {
		if !cfg.IsolationEnabled {
			log.Fatalf("Error: Siemens S7comm PLC service requires container isolation (must specify --isolation)")
		}
		mgr.AddService(s7comm.NewS7CommService(cfg.S7commPort), cfg.IsolationEnabled)
	}
	
	shell := ui.NewShell(mgr)

	// If NOT a TTY, ensure we keep logging to stdout
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		infoStdout := syslog.NewInfoWriter(os.Stdout)
		mgr.SetLogger(infoStdout)
		css.SetLogger(os.Stdout)
		syslog.AddWriter(os.Stdout)
		if mgr.IsoEngine != nil {
			mgr.IsoEngine.SetLogger(infoStdout)
		}
	}

	// Start all services enabled via flags
	if err := mgr.StartAll(); err != nil {
		log.Printf("Warning: Failed to start all services: %v", err)
	}
	
	if err := shell.Run(); err != nil {
		log.Fatalf("UI error: %v", err)
	}
}
