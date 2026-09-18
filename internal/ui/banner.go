package ui

import (
	"fmt"
	"strings"
)

const (
	ColorReset       = "\033[0m"
	ColorYellow      = "\033[33m"
	ColorGold        = "\033[38;5;214m"
	ColorCyan        = "\033[36m"
	ColorGreen       = "\033[32m"
	ColorBrightGreen = "\033[38;5;46m"
	ColorPhosphor    = "\033[38;5;82m"
	ColorRed         = "\033[31m"
)

const Banner = `
        .---.           .---.           .---.
       /     \         /     \         /     \
   .---\  _  /---. .---\  _  /---. .---\  _  /---.
  /     \/ \/     \     \/ \/     \     \/ \/     \
  \  _  /\_/\  _  /\  _  /\_/\  _  /\  _  /\_/\  _  /
   \/ \/     \/ \/  \/ \/     \/ \/  \/ \/     \/ \/
   /\_/\  _  /\_/\  _  /\_/\  _  /\_/\  _  /\_/\
  \     \/ \/     \/ \/     \/ \/     \/ \/     /
   '---/  _  \---/  _  \---/  _  \---/  _  \---'
       \     /   \     /   \     /   \     /
        '---'     '---'     '---'     '---'

  _    _  ____  _   _ ________     _______  ____  
 | |  | |/ __ \| \ | |  ____\ \   / / ____|/ __ \ 
 | |__| | |  | |  \| | |__   \ \_/ / |  __| |  | |
 |  __  | |  | | . ' |  __|   \   /| | |_ | |  | |
 | |  | | |__| | |\  | |____   | | | |__| | |__| |
 |_|  |_|\____/|_| \_|______|  |_|  \_____|\____/ 
`

const Version = "v0.5.8"

func PrintBanner() {
	fmt.Printf("%s%s%s\n", ColorBrightGreen, Banner, ColorReset)
	fmt.Printf("%s Honeygo %s - Detect. Isolate. Contain.%s\n", ColorPhosphor, Version, ColorReset)
	fmt.Printf("%s----------------------------------------------------------%s\n", ColorGreen, ColorReset)
}

// FormatCLIHelp returns a clean, categorized, and readable command-line help screen.
func FormatCLIHelp() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%sHoneygo %s - Multi-Protocol Honeypot & Container Isolation Framework%s\n\n", ColorPhosphor, Version, ColorReset))
	sb.WriteString("Usage:\n")
	sb.WriteString("  honeygo [flags]\n\n")

	sb.WriteString("Core & Engine Options:\n")
	sb.WriteString("  --isolation                  Enable rootless container sandbox isolation\n")
	sb.WriteString("  --db <path>                  Path to SQLite database (default: \"honeygo.db\")\n")
	sb.WriteString("  --clear-db                   Purge all data from the database on startup\n\n")

	sb.WriteString("Honeypot Services:\n")
	sb.WriteString("  --ssh                        Enable SSH honeypot (default port: 2222)\n")
	sb.WriteString("  --ssh-port <port>            SSH honeypot port (default: 2222)\n")
	sb.WriteString("  --telnet                     Enable Telnet honeypot (default port: 2323)\n")
	sb.WriteString("  --telnet-port <port>         Telnet honeypot port (default: 2323)\n")
	sb.WriteString("  --web                        Enable Web/HTTP honeypot (default port: 8080)\n")
	sb.WriteString("  --web-port <port>            Web honeypot port (default: 8080)\n")
	sb.WriteString("  --web-profile <profile>      Web profile: apache, iis, cisco, aws-canary, pizzashop, or file path (default: \"apache\")\n")
	sb.WriteString("  --web-ssl                    Enable SSL/TLS encryption on Web honeypot (requires ./certs/)\n")
	sb.WriteString("  --vnc                        Enable VNC honeypot (default port: 5900)\n")
	sb.WriteString("  --vnc-port <port>            VNC honeypot port (default: 5900)\n\n")

	sb.WriteString("Industrial Control Systems (ICS / SCADA):\n")
	sb.WriteString("  --modbus                     Enable Modbus TCP PLC honeypot (default port: 502, isolated)\n")
	sb.WriteString("  --modbus-port <port>         Modbus TCP port (default: 502)\n")
	sb.WriteString("  --modbus-profile <profile>   Modbus PLC profile: schneider, common-q, triconex (default: \"schneider\")\n")
	sb.WriteString("  --s7comm                     Enable Siemens S7comm PLC honeypot (default port: 102, isolated)\n")
	sb.WriteString("  --s7comm-port <port>         Siemens S7comm port (default: 102)\n\n")

	sb.WriteString("Central Storage Server (CSS) & Clustering:\n")
	sb.WriteString("  --css-server                 Launch in Central Storage Server (CSS) mode (default: HTTP)\n")
	sb.WriteString("  --css-port <port>            CSS server & WebUI dashboard port (default: 8090)\n")
	sb.WriteString("  --css-url <url>              Connect as remote sensor to CSS server (e.g. https://css.corp.internal:8090)\n")
	sb.WriteString("  --css-token <token>          Authentication Bearer token for CSS server or sensor\n")
	sb.WriteString("  --css-auth                   Enforce token authentication on CSS server\n")
	sb.WriteString("  -k, --insecure               Ignore self-signed SSL/TLS certificates when connecting to CSS\n")
	sb.WriteString("  --sensor-id <id>             Custom identifier for this sensor node (default: auto-generated)\n")
	sb.WriteString("  --sensor-ttl <seconds>       Sensor checkin TTL heartbeat interval in seconds (default: 15)\n")
	sb.WriteString("  --analytics                  Start standalone WebUI Analytics Dashboard (default port: 8090)\n")
	sb.WriteString("  --analytics-port <port>      WebUI Analytics Dashboard port (default: 8090)\n")
	sb.WriteString("  --ssl                        Enable SSL/TLS on WebUI & CSS server (requires ./certs/server.crt and ./certs/server.key)\n\n")

	sb.WriteString("Threat Intelligence & Alerting:\n")
	sb.WriteString("  --carto-key <key>            API key for CARTO threat heatmap basemaps\n")
	sb.WriteString("  --misp-url <url>             MISP server URL for threat sharing (e.g. https://misp.corp.internal)\n")
	sb.WriteString("  --misp-key <key>             MISP API Auth Key\n")
	sb.WriteString("  --misp-skip-verify           Skip SSL/TLS verification for MISP\n")
	sb.WriteString("  --telegram-token <token>     Telegram Bot API Token for intrusion alerts\n")
	sb.WriteString("  --telegram-chat-id <id>      Telegram Chat ID for alerts\n\n")

	sb.WriteString("Output & Logging Control:\n")
	sb.WriteString("  --info, --verbose            Enable live streaming of informational messages (sensors, events, errors; default: disabled)\n\n")

	sb.WriteString("Help & Information:\n")
	sb.WriteString("  -h, --help                   Show this categorized help message and exit\n")
	sb.WriteString("  -v, --version                Display version information and exit\n\n")

	sb.WriteString("Examples:\n")
	sb.WriteString("  # Start interactive CRT shell with default settings:\n")
	sb.WriteString("  ./honeygo\n\n")
	sb.WriteString("  # Start with container isolation, SSH on port 22, and Web honeypot:\n")
	sb.WriteString("  ./honeygo --isolation --ssh --ssh-port=22 --web --web-profile=aws-canary\n\n")
	sb.WriteString("  # Launch Central Storage Server (CSS) with SSL/TLS on port 8090:\n")
	sb.WriteString("  ./honeygo --css-server --css-port=8090 --ssl --css-token=Secret123\n\n")
	sb.WriteString("  # Connect as remote sensor to CSS server over HTTPS, ignoring self-signed certs (-k):\n")
	sb.WriteString("  ./honeygo --css-url=https://css.internal:8090 -k --css-token=Secret123 --sensor-id=sensor-dmz-01 --sensor-ttl=30\n")

	return sb.String()
}
