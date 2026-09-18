package ui

import (
	"fmt"
	"strings"
)

// RenderHelp returns structured, in-depth help text based on the provided arguments.
// Examples:
//   RenderHelp(nil) -> Root help menu with single /css entry
//   RenderHelp([]string{"start"}) -> In-depth /start help
//   RenderHelp([]string{"start", "ssh"}) -> In-depth /start ssh help with examples
//   RenderHelp([]string{"services", "ssh"}) -> In-depth /services ssh details
//   RenderHelp([]string{"css", "server"}) -> In-depth /css server help
func RenderHelp(args []string) string {
	if len(args) == 0 {
		return renderRootHelp()
	}

	cmd := strings.ToLower(strings.TrimPrefix(args[0], "/"))
	sub := ""
	if len(args) > 1 {
		sub = strings.ToLower(strings.TrimPrefix(args[1], "/"))
	}

	switch cmd {
	case "services":
		return renderServicesHelp(sub)
	case "start":
		return renderStartHelp(sub)
	case "stop":
		return renderStopHelp(sub)
	case "status":
		return renderStatusHelp()
	case "css":
		return renderCSSHelp(sub)
	case "webprofile":
		return renderWebProfileHelp(sub)
	case "modbusprofile":
		return renderModbusProfileHelp(sub)
	case "recon":
		return renderReconHelp(sub)
	case "canary":
		return renderCanaryHelp()
	case "logs":
		return renderLogsHelp(sub)
	case "creds", "credentials":
		return renderCredsHelp()
	case "analytics":
		return renderAnalyticsHelp(sub)
	case "telegram":
		return renderTelegramHelp()
	case "misp":
		return renderMISPHelp(sub)
	case "syslog":
		return renderSyslogHelp(sub)
	case "info", "verbose", "toggle":
		return renderInfoHelp()
	case "cleardb":
		return renderClearDBHelp()
	case "clear":
		return renderClearHelp()
	case "exit", "quit":
		return renderExitHelp()
	default:
		return fmt.Sprintf("[yellow]Unknown command '%s'. Type [white]/help[yellow] to view all available commands.[white]\n", cmd)
	}
}

func renderRootHelp() string {
	var sb strings.Builder
	sb.WriteString("[cyan]Available Commands:[white]\n")
	sb.WriteString("  [green]/services[white] [svc]         - List all service types and isolation status\n")
	sb.WriteString("  [green]/status[white]                 - Show only active running services and isolation status\n")
	sb.WriteString("  [green]/start[white] <svc> <p> [opts]  - Start a honeypot service on a specified port\n")
	sb.WriteString("  [green]/stop[white] <svc> [port]      - Stop a service (all instances or specific port)\n")
	sb.WriteString("  [green]/logs[white] [web|req|dl|exp]  - View connection summaries, inspect/download raw requests, or export logs\n")
	sb.WriteString("  [green]/creds[white]                  - View captured credentials (passwords, usernames, hashes)\n")
	sb.WriteString("  [green]/webprofile[white] <profile>   - Set active Web honeypot profile (apache, iis, cisco, aws-canary, pizzashop)\n")
	sb.WriteString("  [green]/modbusprofile[white] <prof>   - Set active Modbus PLC emulation profile (schneider, common-q, triconex)\n")
	sb.WriteString("  [green]/analytics[white] [cmd] [port] - Control WebUI analytics dashboard\n")
	sb.WriteString("  [green]/telegram[white] <tok> <id>    - Configure real-time intrusion alerts\n")
	sb.WriteString("  [green]/misp[white] [url] [key] ...   - Configure MISP threat sharing and event dispatch\n")
	sb.WriteString("  [green]/css[white] [subcommand]       - Central Storage Server (CSS) configuration & sensor clustering\n")
	sb.WriteString("  [green]/recon[white] [subcommand]     - Secondary IP recon, C2 dropper & canary threat intelligence\n")
	sb.WriteString("  [green]/canary[white] <ip> [info]     - Manually record a canary token hit IP\n")
	sb.WriteString("  [green]/syslog[white] [cat] [limit]   - View structured operational & troubleshooting audit logs\n")
	sb.WriteString("  [green]/info[white] [on|off|status]   - Toggle live streaming of informational messages (events, errors, sensors)\n")
	sb.WriteString("  [green]/cleardb[white]                - Purge all data from SQLite database\n")
	sb.WriteString("  [green]/clear[white]                  - Clear the log view\n")
	sb.WriteString("  [green]/exit[white]                   - Stop all services and exit Honeygo\n\n")
	sb.WriteString("[yellow]In-Depth Command Help:[white]\n")
	sb.WriteString("  Type [white]/help <command>[yellow] for command details (e.g. [white]/help start[yellow], [white]/help css[yellow], [white]/help services[yellow]).\n")
	sb.WriteString("  Type [white]/help <command> <sub-option>[yellow] for sub-option details (e.g. [white]/help start ssh[yellow], [white]/help css server[yellow], [white]/help services modbus[yellow]).\n")
	return sb.String()
}

func renderServicesHelp(sub string) string {
	switch sub {
	case "ssh":
		return `[cyan]Service Details: SSH (Secure Shell)[white]
  [yellow]Protocol:[white]    ssh (RFC 4251, 4252, 4253, 4254)
  [yellow]Default Port:[white] 2222
  [yellow]Isolation:[white]   [yellow]Supports Isolation[white] (Container Sandbox or Native Mock)
  [yellow]Description:[white] Emulates an SSH server capturing passwords, interactive challenge responses,
               and remote terminal execution. When container isolation is enabled, an ephemeral
               guest container is spawned per session with automatic TTL expiration.
  [yellow]Capture:[white]     Usernames, passwords, executed commands, terminal session I/O, client IPs.

[cyan]Example Commands:[white]
  [green]/start ssh 2222[white]
      Start SSH service with native mock terminal on port 2222.
  [green]/start ssh 2222 --isolated[white]
      Start SSH service with container isolation on port 2222.
  [green]/start ssh 22 --isolated --ttl 600[white]
      Start isolated SSH service on port 22 with a 10-minute session TTL.
  [green]/stop ssh[white]
      Stop all running SSH instances.
`
	case "telnet":
		return `[cyan]Service Details: Telnet[white]
  [yellow]Protocol:[white]    telnet (RFC 854, 855)
  [yellow]Default Port:[white] 2323
  [yellow]Isolation:[white]   [yellow]Supports Isolation[white] (Container Sandbox or Native Mock)
  [yellow]Description:[white] Full-duplex Telnet server implementing standard IAC negotiation (ECHO, SGA,
               WILL/WONT), password echo suppression, and CR NUL / CR LF handling. Supports
               both isolated container handoff and fallback simulated mock shells.
  [yellow]Capture:[white]     Login usernames, passwords, executed shell commands, client IPs.

[cyan]Example Commands:[white]
  [green]/start telnet 2323[white]
      Start Telnet service on port 2323 with native mock shell.
  [green]/start telnet 23 --isolated --ttl 300[white]
      Start isolated Telnet service on port 23 with a 5-minute container session TTL.
  [green]/stop telnet 2323[white]
      Stop Telnet service on port 2323.
`
	case "web":
		return `[cyan]Service Details: Web (HTTP Honeypot)[white]
  [yellow]Protocol:[white]    web (HTTP/1.1)
  [yellow]Default Port:[white] 8080
  [yellow]Isolation:[white]   [red]Not Isolated[white] (Native Profile-based HTTP Honeypot)
  [yellow]Description:[white] High-interaction HTTP emulator supporting customizable server profiles (Apache,
               Microsoft IIS, Cisco IOS, AWS Canary Tokens, PizzaShop) or custom raw response templates.
               Extracts Basic Auth credentials, form POST credentials, and tracks canary probes.
  [yellow]Profiles:[white]    apache, iis, cisco, aws-canary, pizzashop, or custom template file path.
  [yellow]Capture:[white]     HTTP headers, Basic Auth credentials, POST login parameters, canary hits.

[cyan]Example Commands:[white]
  [green]/start web 8080 --profile apache[white]
      Start Web honeypot on port 8080 mimicking Apache 2.4.
  [green]/start web 8080 --profile aws-canary[white]
      Start Web honeypot serving AWS decoy credentials, .env files, and cloud tokens.
  [green]/start web 8080 --profile pizzashop[white]
      Start Web honeypot serving unhinged 90s pizza marketing page with AI/LLM discovery endpoints.
  [green]/start web 80 --profile iis[white]
      Start Web honeypot on port 80 mimicking Microsoft IIS 10.0.
  [green]/webprofile cisco[white]
      Dynamically switch all running Web services to Cisco IOS 401 Basic Auth profile.
  [green]/stop web[white]
      Stop all running Web services.
`
	case "vnc":
		return `[cyan]Service Details: VNC (Virtual Network Computing)[white]
  [yellow]Protocol:[white]    vnc (RFB 003.008)
  [yellow]Default Port:[white] 5900
  [yellow]Isolation:[white]   [yellow]Supports Isolation[white] (Container Sandbox or Native Mock)
  [yellow]Description:[white] VNC honeypot implementing RFB handshake and Security Type 2 (VNC Auth). Captures
               DES challenge-response hashes and automatically recovers common dictionary passwords.
               When isolation is enabled, bridges authenticated attackers directly into a sandboxed GUI.
  [yellow]Capture:[white]     RFB version, VNC auth response hashes, decrypted passwords, client IPs.

[cyan]Example Commands:[white]
  [green]/start vnc 5900[white]
      Start VNC honeypot capturing credentials on port 5900.
  [green]/start vnc 5900 --isolated --ttl 300[white]
      Start VNC honeypot with isolated desktop container bridge on port 5900.
  [green]/stop vnc[white]
      Stop all running VNC services.
`
	case "modbus":
		return `[cyan]Service Details: Modbus TCP (Industrial Control Systems / SCADA)[white]
  [yellow]Protocol:[white]    modbus (MBAP / Modbus Application Protocol)
  [yellow]Default Port:[white] 502
  [yellow]Isolation:[white]   [green]Isolated[white] (Mandatory Container Sandbox)
  [yellow]Description:[white] Industrial PLC honeypot implementing Modbus TCP function codes (0x01 Read Coils,
               0x02 Read Discrete Inputs, 0x03 Read Holding Registers, 0x04 Read Input Registers,
               0x05 Write Single Coil, 0x06 Write Single Register, 0x10 Write Multiple Registers,
               0x11 Report Server ID, 0x2B Read Device Identification MEI 0x0E).
  [yellow]Profiles:[white]    schneider (Modicon M221), common-q (Westinghouse Nuclear RPS), triconex (Invensys TMR SIS).
  [yellow]Capture:[white]     PLC function codes, register/coil read/write payloads, unit IDs, raw hex frames.

[cyan]Example Commands:[white]
  [green]/start modbus 502[white]
      Start Modbus PLC honeypot with Schneider Modicon M221 profile on port 502.
  [green]/start modbus 502 --profile common-q[white]
      Start Modbus PLC honeypot with Westinghouse Nuclear Reactor Protection System profile.
  [green]/start modbus 502 --profile triconex[white]
      Start Modbus PLC honeypot with Invensys Triconex Triple Modular Redundancy SIS profile.
  [green]/modbusprofile common-q[white]
      Dynamically switch running Modbus PLC device identity and register tables.
  [green]/stop modbus[white]
      Stop Modbus TCP PLC service.
`
	case "s7comm":
		return `[cyan]Service Details: Siemens S7comm (ISO-on-TCP / COTP)[white]
  [yellow]Protocol:[white]    s7comm (Siemens Step 7 Industrial PLC Protocol)
  [yellow]Default Port:[white] 102
  [yellow]Isolation:[white]   [green]Isolated[white] (Mandatory Container Sandbox)
  [yellow]Description:[white] Industrial honeypot implementing ISO-on-TCP (RFC 1006 TPKT version 3), COTP
               (Connection Request/Confirm CR/CC), S7comm Setup Communication, SZL System
               Status List identification queries (Simulating Siemens S7-1200 CPU 1214C),
               and Read/Write Variable functions.
  [yellow]Capture:[white]     COTP connection parameters, S7comm ROSCTR messages, SZL queries, read/write payloads.

[cyan]Example Commands:[white]
  [green]/start s7comm 102[white]
      Start Siemens S7comm PLC honeypot on port 102.
  [green]/start s7comm 102 --ttl 600[white]
      Start Siemens S7comm PLC honeypot with 10-minute container TTL.
  [green]/stop s7comm[white]
      Stop Siemens S7comm service.
`
	case "css":
		return `[cyan]Service Details: CSS (Central Storage Server & Analytics WebUI)[white]
  [yellow]Protocol:[white]    css (Central Storage Server & Web Analytics Dashboard)
  [yellow]Default Port:[white] 8090
  [yellow]Isolation:[white]   [red]Not Isolated[white] (Native Central Storage Server & WebUI)
  [yellow]Description:[white] Central log aggregator and real-time CRT phosphor WebUI dashboard. In CSS Server
               mode, receives live telemetry from remote Honeygo sensors and serves OpenCTI threat
               feeds (STIX 2.1, TAXII 2.1, RSS 2.0, CSV).
  [yellow]Capture:[white]     Central database aggregation across multiple honeypot sensors.

[cyan]Example Commands:[white]
  [green]/start css 8090[white]
      Start Central Storage Server & WebUI dashboard on port 8090.
  [green]/css server start 8090 --token SecretKey123[white]
      Start CSS Server with mandatory token authentication on port 8090.
  [green]/stop css[white]
      Stop Central Storage Server / analytics dashboard.
`
	default:
		return `[cyan]Command: /services[white]
  [yellow]Syntax:[white]      /services [service_name]
  [yellow]Description:[white] Lists all supported honeypot service types, their container isolation capabilities,
               and the live isolation state of all active instances.

[cyan]Available Service Types:[white]
  - [white]ssh[cyan]      : Secure Shell honeypot ([yellow]Supports Isolation[white])
  - [white]telnet[cyan]   : Telnet honeypot ([yellow]Supports Isolation[white])
  - [white]web[cyan]      : HTTP honeypot ([red]Not Isolated[white])
  - [white]vnc[cyan]      : VNC honeypot ([yellow]Supports Isolation[white])
  - [white]modbus[cyan]   : Modbus TCP Industrial PLC honeypot ([green]Isolated[white])
  - [white]s7comm[cyan]   : Siemens S7comm Industrial PLC honeypot ([green]Isolated[white])
  - [white]css[cyan]      : Central Storage Server & Analytics WebUI ([red]Not Isolated[white])

[yellow]Tip:[white] Type [white]/help services <service>[yellow] for in-depth details on a specific service (e.g. [white]/help services ssh[yellow], [white]/help services modbus[yellow]).
`
	}
}

func renderStartHelp(sub string) string {
	switch sub {
	case "ssh":
		return `[cyan]Command: /start ssh[white]
  [yellow]Syntax:[white]  /start ssh <port> [--isolated] [--ttl <seconds>]
  [yellow]Options:[white]
    <port>           Port number to bind (e.g. 2222 or 22)
    --isolated       Enable ephemeral container sandbox per attacker session
    --ttl <seconds>  Session container TTL in seconds (default: 300)

[cyan]Examples:[white]
  [green]/start ssh 2222[white]
      Start SSH honeypot on port 2222 with native mock shell.
  [green]/start ssh 2222 --isolated[white]
      Start SSH honeypot on port 2222 with container isolation.
  [green]/start ssh 22 --isolated --ttl 600[white]
      Start isolated SSH honeypot on port 22 with 10-minute session TTL.
`
	case "telnet":
		return `[cyan]Command: /start telnet[white]
  [yellow]Syntax:[white]  /start telnet <port> [--isolated] [--ttl <seconds>]
  [yellow]Options:[white]
    <port>           Port number to bind (e.g. 2323 or 23)
    --isolated       Enable ephemeral container sandbox per attacker session
    --ttl <seconds>  Session container TTL in seconds (default: 300)

[cyan]Examples:[white]
  [green]/start telnet 2323[white]
      Start Telnet honeypot on port 2323 with native mock shell.
  [green]/start telnet 23 --isolated --ttl 300[white]
      Start isolated Telnet honeypot on port 23 with 5-minute session TTL.
`
	case "web":
		return `[cyan]Command: /start web[white]
  [yellow]Syntax:[white]  /start web <port> [--profile <profile_name>]
  [yellow]Options:[white]
    <port>                Port number to bind (e.g. 8080 or 80)
    --profile <profile>   Server profile (apache, iis, cisco, aws-canary, pizzashop, or file path)

[cyan]Examples:[white]
  [green]/start web 8080[white]
      Start Web honeypot on port 8080 with default Apache profile.
  [green]/start web 8080 --profile aws-canary[white]
      Start Web honeypot serving AWS cloud credentials, .env, and decoy canary tokens.
  [green]/start web 8080 --profile pizzashop[white]
      Start Web honeypot with unhinged 90s pizza marketing page and AI/LLM discovery endpoints.
  [green]/start web 80 --profile iis[white]
      Start Web honeypot on port 80 mimicking Microsoft IIS 10.
  [green]/start web 8080 --profile /home/user/custom_portal.txt[white]
      Start Web honeypot with a custom multi-path HTTP response template file.
`
	case "modbus":
		return `[cyan]Command: /start modbus[white]
  [yellow]Syntax:[white]  /start modbus <port> [--profile <profile_name>] [--ttl <seconds>]
  [yellow]Note:[white]    Modbus TCP PLC services run with mandatory container isolation.
  [yellow]Options:[white]
    <port>                Port number to bind (e.g. 502)
    --profile <profile>   PLC profile (schneider, common-q, triconex)
    --ttl <seconds>       Session container TTL in seconds (default: 300)

[cyan]Examples:[white]
  [green]/start modbus 502[white]
      Start Modbus PLC honeypot on port 502 with default Schneider Modicon M221 profile.
  [green]/start modbus 502 --profile common-q[white]
      Start Modbus PLC honeypot with Westinghouse Nuclear Reactor Protection System profile.
  [green]/start modbus 502 --profile triconex[white]
      Start Modbus PLC honeypot with Invensys Triconex Triple Modular Redundancy SIS profile.
`
	case "s7comm":
		return `[cyan]Command: /start s7comm[white]
  [yellow]Syntax:[white]  /start s7comm <port> [--ttl <seconds>]
  [yellow]Note:[white]    Siemens S7comm PLC services run with mandatory container isolation.
  [yellow]Options:[white]
    <port>           Port number to bind (e.g. 102)
    --ttl <seconds>  Session container TTL in seconds (default: 300)

[cyan]Examples:[white]
  [green]/start s7comm 102[white]
      Start Siemens S7comm (ISO-on-TCP) industrial PLC honeypot on port 102.
  [green]/start s7comm 102 --ttl 600[white]
      Start Siemens S7comm PLC honeypot with a 10-minute session TTL.
`
	case "vnc":
		return `[cyan]Command: /start vnc[white]
  [yellow]Syntax:[white]  /start vnc <port> [--isolated] [--ttl <seconds>]
  [yellow]Options:[white]
    <port>           Port number to bind (e.g. 5900)
    --isolated       Bridge authenticated attackers into an isolated sandboxed desktop
    --ttl <seconds>  Session container TTL in seconds (default: 300)

[cyan]Examples:[white]
  [green]/start vnc 5900[white]
      Start VNC honeypot capturing credentials on port 5900.
  [green]/start vnc 5900 --isolated --ttl 300[white]
      Start isolated VNC honeypot on port 5900 with 5-minute container session TTL.
`
	case "css":
		return `[cyan]Command: /start css[white]
  [yellow]Syntax:[white]  /start css <port>
  [yellow]Options:[white]
    <port>           Port number for Central Storage Server and WebUI (e.g. 8090)

[cyan]Examples:[white]
  [green]/start css 8090[white]
      Start Central Storage Server & WebUI dashboard on port 8090.
`
	default:
		return `[cyan]Command: /start[white]
  [yellow]Syntax:[white]      /start <service> <port> [--profile <profile>] [--isolated] [--ttl <seconds>]
  [yellow]Description:[white] Starts a new honeypot service listener on the specified port.

[cyan]Arguments & Flags:[white]
  [white]<service>[cyan]         : Protocol name (ssh, telnet, web, vnc, modbus, s7comm, css)
  [white]<port>[cyan]            : Port number to bind
  [white]--profile <prof>[cyan]  : Device/service profile (for web and modbus)
  [white]--isolated[cyan]        : Enable guest container sandbox isolation
  [white]--ttl <seconds>[cyan]   : Session container TTL timeout in seconds (default: 300)

[cyan]Examples:[white]
  [green]/start ssh 2222 --isolated[white]
  [green]/start web 8080 --profile aws-canary[white]
  [green]/start modbus 502 --profile common-q[white]
  [green]/start s7comm 102[white]

[yellow]Tip:[white] Type [white]/help start <service>[yellow] for service-specific start options (e.g. [white]/help start ssh[yellow], [white]/help start web[yellow]).
`
	}
}

func renderStopHelp(sub string) string {
	if sub != "" {
		return fmt.Sprintf(`[cyan]Command: /stop %s[white]
  [yellow]Syntax:[white]  /stop %s [port]
  [yellow]Options:[white]
    [port]   Optional port number. If omitted, stops ALL running %s instances.

[cyan]Examples:[white]
  [green]/stop %s[white]
      Stop all running %s instances.
  [green]/stop %s 2222[white]
      Stop specific %s instance running on port 2222.
`, sub, sub, sub, sub, sub, sub, sub)
	}

	return `[cyan]Command: /stop[white]
  [yellow]Syntax:[white]      /stop <service> [port]
  [yellow]Description:[white] Stops a running honeypot service. If a port is specified, only that instance
               is stopped. If no port is specified, all instances of that protocol are stopped.

[cyan]Examples:[white]
  [green]/stop ssh[white]
      Stop all active SSH services.
  [green]/stop ssh 2222[white]
      Stop only the SSH service running on port 2222.
  [green]/stop web 8080[white]
      Stop the Web service running on port 8080.
  [green]/stop modbus[white]
      Stop all Modbus TCP PLC instances.
`
}

func renderStatusHelp() string {
	return `[cyan]Command: /status[white]
  [yellow]Syntax:[white]      /status
  [yellow]Description:[white] Displays all currently active honeypot services, listening ports,
               running states, and container isolation status badges ([Isolated] vs [Not Isolated]).

[cyan]Example Output:[white]
  Active Running Services:
    ● [ssh     ] Port 2222: Running [Isolated]
    ● [web     ] Port 8080: Running [Not Isolated]
    ● [modbus  ] Port 502:  Running [Isolated]
`
}

func renderCSSHelp(sub string) string {
	switch sub {
	case "server":
		return `[cyan]Command: /css server[white]
  [yellow]Syntax:[white]  /css server start <port> [--token <secret_token>] [--ssl]
          /css server stop
  [yellow]Description:[white] Starts or stops the Central Storage Server (CSS) mode. When active,
               the node acts as the central aggregator for remote sensors and serves OpenCTI feeds.
               Default protocol is HTTP. Use --ssl to enable HTTPS (requires cert and key in ./certs/).

[cyan]Examples:[white]
  [green]/css server start 8090[white]
      Start CSS server on port 8090 over HTTP.
  [green]/css server start 8090 --token SecretKey123[white]
      Start CSS server on port 8090 requiring Bearer token authentication over HTTP.
  [green]/css server start 8090 --ssl --token SecretKey123[white]
      Start CSS server on port 8090 requiring Bearer token authentication over HTTPS.
  [green]/css server stop[white]
      Stop the CSS server.
`
	case "connect":
		return `[cyan]Command: /css connect[white]
  [yellow]Syntax:[white]  /css connect <url> [--token <token>] [--sensor-id <id>] [--ttl <seconds>] [-k]
  [yellow]Description:[white] Connects this Honeygo node to a remote Central Storage Server (CSS).
               When connected as a sensor, all captured connection attempts, credentials, and
               commands are forwarded to the central server in real-time.
               Use -k to ignore self-signed certificates on the CSS server.

[cyan]Examples:[white]
  [green]/css connect http://css.corp.internal:8090[white]
      Connect to CSS server using default auto-generated sensor ID and 15s checkin TTL.
  [green]/css connect https://css.corp.internal:8090 -k[white]
      Connect to CSS server over HTTPS ignoring self-signed certificate warnings (-k).
  [green]/css connect https://css.corp.internal:8090 --token SecretKey123 --sensor-id sensor-dmz-01 --ttl 30 -k[white]
      Connect to CSS server with token authentication, custom sensor name, 30s checkin TTL, and -k self-signed SSL bypass.
`
	case "ttl", "interval":
		return `[cyan]Command: /css ttl[white]
  [yellow]Syntax:[white]  /css ttl <seconds>
          /css ttl
  [yellow]Description:[white] Configures or displays the sensor checkin TTL (heartbeat frequency in seconds).
               When running in sensor mode, heartbeats are dynamically sent at this interval to notify
               the CSS server of sensor health and retrieve pending remote commands.

[cyan]Examples:[white]
  [green]/css ttl 30[white]
      Set sensor checkin TTL to 30 seconds.
  [green]/css ttl 60[white]
      Set sensor checkin TTL to 60 seconds (1 minute).
  [green]/css ttl[white]
      Display the current sensor checkin TTL setting.
`
	case "disconnect":
		return `[cyan]Command: /css disconnect[white]
  [yellow]Syntax:[white]  /css disconnect
  [yellow]Description:[white] Disconnects from the remote Central Storage Server (CSS) and reverts
               the node back to standalone local logging mode.
`
	case "sensors":
		return `[cyan]Command: /css sensors[white]
  [yellow]Syntax:[white]  /css sensors
  [yellow]Description:[white] Lists all connected remote sensor nodes, IP addresses, online statuses,
               checkin TTLs, total ingested events, and active running services with isolation badges.
`
	case "name", "rename":
		return `[cyan]Command: /css name[white]
  [yellow]Syntax:[white]  /css name <sensor_id> <display_name>
  [yellow]Description:[white] Sets or updates a human-readable display name / label for a connected sensor node.

[cyan]Examples:[white]
  [green]/css name sensor-node-1 DMZ Edge Sensor - Virginia[white]
      Set a custom display name for sensor-node-1.
`
	case "start":
		return `[cyan]Command: /css start[white]
  [yellow]Syntax:[white]  /css start <sensor_id> <protocol> [port] [--isolated] [--profile <profile>] [--ttl <seconds>]
  [yellow]Description:[white] Remotely starts or reconfigures a honeypot service on a connected sensor node,
               including custom port, isolation sandbox mode, deception profile, and session TTL.

[cyan]Examples:[white]
  [green]/css start sensor-01 ssh 2222 --isolated --ttl 600[white]
      Start isolated SSH honeypot on sensor-01 with a 10-minute session TTL.
  [green]/css start sensor-01 web 8080 --profile pizzashop --ttl 300[white]
      Start HTTP honeypot on sensor-01 using pizzashop profile and 300s TTL.
`
	case "stop":
		return `[cyan]Command: /css stop[white]
  [yellow]Syntax:[white]  /css stop <sensor_id> <protocol> [port]
  [yellow]Description:[white] Remotely stops a running honeypot service listener on a connected sensor node.

[cyan]Examples:[white]
  [green]/css stop sensor-01 ssh 2222[white]
      Stop SSH service on port 2222 on sensor-01.
`
	case "token":
		return `[cyan]Command: /css token[white]
  [yellow]Syntax:[white]  /css token <secret_token>
          /css token off
  [yellow]Description:[white] Configures or disables Bearer token authentication for incoming sensor
               connections and OpenCTI threat feed endpoints.

[cyan]Examples:[white]
  [green]/css token MySecureToken2026[white]
      Enable token authentication.
  [green]/css token off[white]
      Disable token authentication.
`
	case "carto", "cartomap":
		return `[cyan]Command: /css carto[white]
  [yellow]Syntax:[white]  /css carto <api_key>
          /css carto off
  [yellow]Description:[white] Configures or clears the API key for CARTO Basemaps raster tiles used
               by the global threat heatmap visualization on the Analytics Dashboard.
               Request a free key at https://carto.com/basemaps/apikey/

[cyan]Examples:[white]
  [green]/css carto YOUR_CARTO_API_KEY[white]
      Set active CARTO Map API key.
  [green]/css carto off[white]
      Clear CARTO Map API key.
`
	default:
		return `[cyan]Command: /css (Central Storage Server)[white]
  [yellow]Syntax:[white]      /css [server|connect|disconnect|ttl|sensors|name|start|stop|token|carto]
  [yellow]Description:[white] Manages Central Storage Server (CSS) clustering, remote sensor forwarding,
               and OpenCTI threat intelligence feeds (STIX 2.1, TAXII 2.1, RSS 2.0, CSV).

[cyan]CSS Subcommands:[white]
  - [white]server start <port> [--token <tok>][cyan] : Start CSS aggregation server
  - [white]server stop[cyan]                         : Stop CSS aggregation server
  - [white]connect <url> [opts][cyan]                : Connect to CSS server as a sensor
  - [white]disconnect[cyan]                          : Disconnect from CSS server
  - [white]ttl <seconds>[cyan]                       : Configure or view sensor checkin TTL heartbeat interval
  - [white]sensors[cyan]                             : List connected sensors, checkin TTLs, and active services
  - [white]start <sensor_id> <proto> [opts][cyan]    : Start service on sensor with port, isolation, profile, TTL
  - [white]stop <sensor_id> <proto> [port][cyan]     : Stop service on sensor
  - [white]name <sensor_id> <display_name>[cyan]     : Set custom display name for a sensor
  - [white]token <token|off>[cyan]                   : Enable or disable token authentication
  - [white]carto <key|off>[cyan]                     : Configure CARTO Map API key for threat heatmap
  - [white](no args)[cyan]                           : Show current CSS status and configuration

[yellow]Tip:[white] Type [white]/help css <subcommand>[yellow] for in-depth sub-option help (e.g. [white]/help css ttl[yellow], [white]/help css connect[yellow], [white]/help css carto[yellow]).
`
	}
}

func renderWebProfileHelp(sub string) string {
	switch sub {
	case "apache":
		return `[cyan]Web Profile: apache[white]
  [yellow]Description:[white] Simulates a standard Apache 2.4.41 Unix / OpenSSL web server responding
               with default "It works!" landing page.
`
	case "iis":
		return `[cyan]Web Profile: iis[white]
  [yellow]Description:[white] Simulates a Microsoft Windows Server running IIS 10.0 responding with
               default "Welcome to IIS 10" landing page.
`
	case "cisco":
		return `[cyan]Web Profile: cisco[white]
  [yellow]Description:[white] Simulates a Cisco IOS Router/Switch administration interface returning
               HTTP 401 Unauthorized with WWW-Authenticate: Basic realm="Cisco Switch".
`
	case "aws-canary", "aws", "canary":
		return `[cyan]Web Profile: aws-canary[white]
  [yellow]Description:[white] Advanced deception profile serving realistic cloud gateway landing pages
               while seeding canary AWS credentials (AKIATU7L4S6WULTSTDSN) in responses to
               /.env, /.aws/credentials, /.aws/config, and credentials files.
`
	case "pizzashop", "pizza", "pizzarea", "pizza_shop":
		return `[cyan]Web Profile: pizzashop[white]
  [yellow]Description:[white] Unhinged, crazy 90s Geocities-style pizza marketing single page with
               embedded Agentic AI & LLM discovery prompt in /.env, /llms.txt, and /llms-full.txt.
`
	default:
		return `[cyan]Command: /webprofile[white]
  [yellow]Syntax:[white]      /webprofile <profile_name|file_path>
  [yellow]Description:[white] Dynamically sets the active Web honeypot profile for all running Web services.

[cyan]Predefined Profiles:[white]
  - [white]apache[cyan]     : Apache 2.4.41 Unix default page
  - [white]iis[cyan]        : Microsoft IIS 10.0 Windows Server page
  - [white]cisco[cyan]      : Cisco IOS 401 Basic Auth challenge
  - [white]aws-canary[cyan] : AWS Cloud Canary token (.env, /.aws/credentials, cloud portal)
  - [white]pizzashop[cyan]  : Unhinged 90s Pizza marketing page, .env, llms.txt & llms-full.txt
  - [white]<file_path>[cyan]: Custom multi-path response template file

[cyan]Examples:[white]
  [green]/webprofile pizzashop[white]
  [green]/webprofile aws-canary[white]
  [green]/webprofile iis[white]
  [green]/webprofile /home/me/profiles/custom_login.txt[white]
`
	}
}

func renderModbusProfileHelp(sub string) string {
	switch sub {
	case "schneider":
		return `[cyan]Modbus PLC Profile: schneider[white]
  [yellow]Device:[white]      Schneider Electric Modicon M221 Factory Automation PLC v2.10
  [yellow]Registers:[white]   40001 (Pressure PSI), 40002 (Temp C), 40003 (Flow Rate), 40004 (Status)
`
	case "common-q", "westinghouse":
		return `[cyan]Modbus PLC Profile: common-q[white]
  [yellow]Device:[white]      Westinghouse Common Q AC160 PM646 Nuclear Safety Controller v4.2.1
  [yellow]Registers:[white]   40001 (RCS Core Pressure 2250 psia), 40002 (Core Exit Temp 582F),
               40003 (Reactor Power 100%), 40004 (RPS Trip Status: ARMED)
`
	case "triconex", "tricon", "invensys":
		return `[cyan]Modbus PLC Profile: triconex[white]
  [yellow]Device:[white]      Invensys Triconex Tricon 3008 TMR SIL-3 Safety Instrumented System v10.4.3
  [yellow]Registers:[white]   40001 (TMR 2oo3 Voter Status), 40002 (ESD Trip Status),
               40003 (Flare Header Pressure), 40004 (SIS State: ACTIVE)
`
	default:
		return `[cyan]Command: /modbusprofile[white]
  [yellow]Syntax:[white]      /modbusprofile <profile_name>
  [yellow]Description:[white] Dynamically switches the active Modbus PLC device identity, MEI 0x2B
               read response, and holding register maps across all running Modbus services.

[cyan]Available Profiles:[white]
  - [white]schneider[cyan] : Schneider Electric Modicon M221 Factory PLC (Default)
  - [white]common-q[cyan]  : Westinghouse Common Q AC160 Nuclear Safety System
  - [white]triconex[cyan]  : Invensys Triconex Tricon 3008 TMR SIL-3 SIS Safety Controller

[cyan]Examples:[white]
  [green]/modbusprofile common-q[white]
  [green]/modbusprofile triconex[white]
  [green]/modbusprofile schneider[white]
`
	}
}

func renderReconHelp(sub string) string {
	switch sub {
	case "list":
		return `[cyan]Command: /recon list[white]
  [yellow]Syntax:[white]  /recon list [limit]
  [yellow]Description:[white] Displays tracked secondary threat infrastructure targets (C2 droppers,
               payload servers, canary triggers) with threat tags, risk scores, and hit counts.
`
	case "add":
		return `[cyan]Command: /recon add[white]
  [yellow]Syntax:[white]  /recon add <ip> [canary|c2] [description]
  [yellow]Description:[white] Manually registers an external IP address for immediate passive PTR reverse
               DNS and GeoIP enrichment and threat scoring.

[cyan]Examples:[white]
  [green]/recon add 198.51.100.23 c2 "Staging payload host"[white]
  [green]/recon add 203.0.113.88 canary "AWS canarytoken trigger alert"[white]
`
	case "canary":
		return `[cyan]Command: /recon canary[white]
  [yellow]Syntax:[white]  /recon canary <ip> [token_info]
  [yellow]Description:[white] Manually records an external Canary Token hit IP for passive enrichment.
`
	case "auto":
		return `[cyan]Command: /recon auto[white]
  [yellow]Syntax:[white]  /recon auto <on|off>
  [yellow]Description:[white] Toggles the background passive OSINT enrichment worker.
`
	case "scanall":
		return `[cyan]Command: /recon scanall[white]
  [yellow]Syntax:[white]  /recon scanall
  [yellow]Description:[white] Triggers immediate passive PTR reverse DNS and GeoIP resolution for all
               pending tracked targets.
`
	default:
		return `[cyan]Command: /recon (Threat Infrastructure & OSINT)[white]
  [yellow]Syntax:[white]      /recon [ip|list|add|canary|auto|scanall]
  [yellow]Description:[white] Tracks secondary staging IPs, C2 dropper servers extracted from executed
               shell scripts, and canary token hits. Performs passive PTR DNS & GeoIP enrichment.

[cyan]Recon Subcommands:[white]
  - [white]<ip>[cyan]                   : Generate instant passive OSINT report for an IP
  - [white]list [limit][cyan]           : List tracked attack infrastructure targets
  - [white]add <ip> [type] [desc][cyan] : Manually register an external target IP
  - [white]canary <ip> [info][cyan]     : Register a canary token hit IP
  - [white]auto <on|off>[cyan]          : Toggle background auto-enrichment worker
  - [white]scanall[cyan]                : Trigger immediate scan for all pending targets
  - [white](no args)[cyan]              : Show Recon engine configuration and metrics summary

[yellow]Tip:[white] Type [white]/help recon <subcommand>[yellow] for in-depth sub-option help (e.g. [white]/help recon add[yellow], [white]/help recon list[yellow]).
`
	}
}

func renderCanaryHelp() string {
	return `[cyan]Command: /canary[white]
  [yellow]Syntax:[white]      /canary <ip> [token_info]
  [yellow]Description:[white] Manually records an external Canary Token hit IP (e.g. from an AWS/Azure
               email alert) for immediate PTR reverse DNS and GeoIP enrichment.

[cyan]Examples:[white]
  [green]/canary 198.51.100.42 "AWS prod-bucket canary hit"[white]
`
}

func renderLogsHelp(sub string) string {
	switch sub {
	case "web":
		return `[cyan]Command: /logs web[white]
  [yellow]Syntax:[white]      /logs web [limit]
  [yellow]Description:[white] Displays recent captured raw HTTP web scan requests with IDs and payloads.
               Defaults to 10 entries if limit is omitted.

[cyan]Examples:[white]
  [green]/logs web[white]
  [green]/logs web 25[white]
`
	case "req", "request", "view", "inspect":
		return `[cyan]Command: /logs req[white]
  [yellow]Syntax:[white]      /logs req <id> [format]
  [yellow]Description:[white] Inspects a specific connection attempt or raw HTTP request by its ID.
               Renders full metadata and formats payload according to the chosen view.

[cyan]Format Options:[white]
  - [white]raw[cyan]     : Exact payload string as originally requested (Default)
  - [white]hex[cyan]     : Standard formatted hex dump (offset, hex bytes, ASCII sidebar)
  - [white]rawhex[cyan]  : Continuous raw hexadecimal stream
  - [white]ascii[cyan]   : Safe ASCII representation with unprintable/binary bytes escaped as \xNN
  - [white]base64[cyan]  : Standard RFC 4648 Base64 encoded payload

[cyan]Examples:[white]
  [green]/logs req 42[white]
  [green]/logs req 42 hex[white]
  [green]/logs req 42 ascii[white]
  [green]/logs req 42 base64[white]
`
	case "download", "save":
		return `[cyan]Command: /logs download[white]
  [yellow]Syntax:[white]      /logs download <id> <filepath> [format]
  [yellow]Description:[white] Downloads and saves a specific captured request payload directly to a local file.
               Guarantees 100% byte fidelity without data loss or corruption.

[cyan]Format Options:[white]
  - [white]raw[cyan]     : Exact raw binary byte stream (.bin / .req) (Default)
  - [white]hex[cyan]     : Formatted hex dump (.hex / .txt)
  - [white]rawhex[cyan]  : Uninterrupted hex string (.hex)
  - [white]ascii[cyan]   : Safe ASCII text with non-printable characters escaped (.txt)
  - [white]base64[cyan]  : Base64 encoded payload (.b64)

[cyan]Examples:[white]
  [green]/logs download 42 /tmp/request_42.bin raw[white]
  [green]/logs download 42 /tmp/request_42_hexdump.hex hex[white]
  [green]/logs download 42 /tmp/request_42_safe.txt ascii[white]
  [green]/logs download 42 /tmp/request_42.b64 base64[white]
`
	case "export":
		return `[cyan]Command: /logs export[white]
  [yellow]Syntax:[white]      /logs export <filepath> [service_protocol] [format]
  [yellow]Description:[white] Exports captured connection attempts and payloads to a file.
               Supports filtering by service and multiple output formats.

[cyan]Services:[white]
  [white]ssh, telnet, web, vnc, modbus, s7comm, all[cyan] (Default: all)

[cyan]Formats:[white]
  - [white]text[cyan]    : Standard human-readable log blocks (Default)
  - [white]raw[cyan]     : Concatenated raw payload streams with metadata headers
  - [white]hex[cyan]     : Full hex dumps with offsets and ASCII sidebars
  - [white]ascii[cyan]   : Safe ASCII representation with \xNN escaping
  - [white]base64[cyan]  : Base64 encoded payload blocks
  - [white]json[cyan]    : Pretty-printed JSON array with all encodings & metadata

[cyan]Examples:[white]
  [green]/logs export /tmp/all_attempts.log[white]
  [green]/logs export /tmp/web_requests.raw web raw[white]
  [green]/logs export /tmp/web_hexdump.hex web hex[white]
  [green]/logs export /tmp/web_requests.json web json[white]
  [green]/logs export /tmp/ssh_attempts.txt ssh text[white]
`
	default:
		return `[cyan]Command: /logs[white]
  [yellow]Syntax:[white]      /logs [web [limit]|req <id> [fmt]|download <id> <fp> [fmt]|export <fp> [svc] [fmt]]
  [yellow]Description:[white] View connection activity summaries, inspect individual HTTP web requests,
               download payloads locally in binary/hex/ascii, or bulk export connection attempts.

[cyan]Subcommands:[white]
  - [white](no args)[cyan]                         : Show recent connection attempts summary
  - [white]web [limit][cyan]                       : Display recent HTTP requests and headers
  - [white]req <id> [fmt][cyan]                    : Inspect request payload (raw, hex, ascii, base64)
  - [white]download <id> <fp> [fmt][cyan]          : Save single request payload directly to a file
  - [white]export <fp> [svc] [fmt][cyan]           : Bulk export logs (text, raw, hex, ascii, base64, json)

[yellow]Tip:[white] Type [white]/help logs req[yellow], [white]/help logs download[yellow], or [white]/help logs export[yellow] for details.
`
	}
}

func renderCredsHelp() string {
	return `[cyan]Command: /creds[white]
  [yellow]Syntax:[white]      /creds
  [yellow]Description:[white] Displays the most recent captured authentication credentials across all
               honeypot protocols (SSH, Telnet, Web Basic Auth, Web Form Logins, VNC).
`
}

func renderAnalyticsHelp(sub string) string {
	switch sub {
	case "start":
		return `[cyan]Command: /analytics start[white]
  [yellow]Syntax:[white]  /analytics start [port] [--ssl]
  [yellow]Description:[white] Starts the standalone WebUI Analytics Dashboard on the specified port (default: 8090).
               Default protocol is HTTP. Use --ssl to enable HTTPS (requires cert and key in ./certs/).
`
	case "stop":
		return `[cyan]Command: /analytics stop[white]
  [yellow]Syntax:[white]  /analytics stop
  [yellow]Description:[white] Stops the running WebUI Analytics Dashboard server.
`
	default:
		return `[cyan]Command: /analytics[white]
  [yellow]Syntax:[white]      /analytics [start|stop] [port] [--ssl]
  [yellow]Description:[white] Controls the embedded WebUI Analytics Dashboard server.

[cyan]Options:[white]
  - [white]start [port] [--ssl][cyan]  : Start WebUI dashboard server (default port: 8090, default HTTP)
  - [white]stop[cyan]                  : Stop WebUI dashboard server
  - [white](no args)[cyan]             : Show current dashboard status and URL
`
	}
}

func renderTelegramHelp() string {
	return `[cyan]Command: /telegram[white]
  [yellow]Syntax:[white]      /telegram <bot_token> <chat_id>
               /telegram off
  [yellow]Description:[white] Configures or disables real-time intrusion alert notifications dispatched
               via Telegram Bot API upon captured credentials and high-risk honeypot hits.

[cyan]Examples:[white]
  [green]/telegram 123456789:ABCDefGhIJKlmNoPQRsTUVwxyZ -1001234567890[white]
  [green]/telegram off[white]
`
}

func renderMISPHelp(sub string) string {
	switch sub {
	case "off":
		return `[cyan]Command: /misp off[white]
  [yellow]Syntax:[white]  /misp off
  [yellow]Description:[white] Disables MISP threat sharing and event dispatching.
`
	default:
		return `[cyan]Command: /misp[white]
  [yellow]Syntax:[white]      /misp <url> <api_key> [--skip-verify]
               /misp off
               /misp
  [yellow]Description:[white] Configures real-time threat intelligence event sharing with a MISP server.
               Automatically creates and dispatches MISP intrusion events for captured credentials,
               shell commands, PLC function codes, and canary triggers.

[cyan]Examples:[white]
  [green]/misp https://misp.corp.internal MyAuthApiKey123[white]
  [green]/misp https://10.0.0.50 MyAuthApiKey123 --skip-verify[white]
  [green]/misp off[white]
  [green]/misp[white] (Show current MISP configuration and statistics)
`
	}
}

func renderSyslogHelp(sub string) string {
	if sub != "" {
		return fmt.Sprintf(`[cyan]Command: /syslog %s[white]
  [yellow]Syntax:[white]  /syslog %s [limit]
  [yellow]Description:[white] Filters structured system audit logs specifically for the '%s' category.

[cyan]Examples:[white]
  [green]/syslog %s 25[white]
  [green]/syslog %s 100[white]
`, strings.ToUpper(sub), strings.ToUpper(sub), strings.ToUpper(sub), strings.ToUpper(sub), strings.ToUpper(sub))
	}

	return `[cyan]Command: /syslog[white]
  [yellow]Syntax:[white]      /syslog [category] [limit]
  [yellow]Description:[white] Displays structured system, operational, and troubleshooting audit logs.

[cyan]Available Categories:[white]
  - [white]SYSTEM[cyan]    : Application startup, shutdown, and flag configuration
  - [white]SERVICE[cyan]   : Honeypot service lifecycle and port bindings
  - [white]ISOLATION[cyan] : Container pool warmer and sandbox guest lifecycle
  - [white]CSS[cyan]       : Central Storage Server and remote sensor heartbeat sync
  - [white]DATABASE[cyan]  : SQLite initialization, migrations, and purges
  - [white]ALERT[cyan]     : Telegram alert dispatches
  - [white]WEBUI[cyan]     : WebUI dashboard and API requests
  - [white]MISP[cyan]      : MISP threat event transmissions

[cyan]Examples:[white]
  [green]/syslog[white]
  [green]/syslog ISOLATION 50[white]
  [green]/syslog CSS 100[white]
`
}

func renderClearDBHelp() string {
	return `[cyan]Command: /cleardb[white]
  [yellow]Syntax:[white]      /cleardb
  [yellow]Description:[white] Purges all recorded connection attempts, captured credentials, executed
               commands, and tracked recon targets from the SQLite database.
`
}

func renderClearHelp() string {
	return `[cyan]Command: /clear[white]
  [yellow]Syntax:[white]      /clear
  [yellow]Description:[white] Clears the active TUI log view window.
`
}

func renderExitHelp() string {
	return `[cyan]Command: /exit[white]
  [yellow]Syntax:[white]      /exit
  [yellow]Description:[white] Gracefully stops all active honeypot services, terminates container
               sandboxes, shuts down background workers, and exits Honeygo.
`
}

func renderInfoHelp() string {
	return `[cyan]Command: /info (aliases: /verbose, /toggle)[white]
  [yellow]Syntax:[white]      /info [on|off|status]
  [yellow]Description:[white] Toggle live streaming of background informational messages (connected sensors,
               routine events, honeypot attempts, and errors) in the console log view.
  [yellow]Default:[white]     Disabled by default. First-time sensor connections are ALWAYS displayed
               unconditionally regardless of this setting.

[cyan]Subcommands:[white]
  - [white]on[cyan]         : Enable live informational streaming (equivalent to --info CLI flag)
  - [white]off[cyan]        : Disable live informational streaming
  - [white]status[cyan]     : Check current streaming status without changing it
  - [white](no args)[cyan]  : Toggle between enabled and disabled

[cyan]Examples:[white]
  [green]/info[white]
  [green]/info on[white]
  [green]/info off[white]
  [green]/info status[white]
`
}

