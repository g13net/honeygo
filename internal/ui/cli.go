package ui

import (
	"encoding/json"
	"fmt"
	"honeygo/internal/alerting"
	"honeygo/internal/css"
	"honeygo/internal/db"
	"honeygo/internal/manager"
	"honeygo/internal/misp"
	"honeygo/internal/recon"
	"honeygo/internal/syslog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"golang.org/x/term"
)

type Shell struct {
	manager *manager.Manager
	app     *tview.Application
	logs    *tview.TextView
	input   *tview.InputField
	history []string
	histIdx int
}

func NewShell(m *manager.Manager) *Shell {
	s := &Shell{
		manager: m,
		app:     tview.NewApplication(),
		history: []string{},
		histIdx: -1,
	}

	// Log View
	s.logs = tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetWordWrap(true).
		SetChangedFunc(func() {
			s.logs.ScrollToEnd()
			s.app.Draw()
		})
	s.logs.SetBorder(true).
		SetTitle(" Honeygo CRT Terminal ").
		SetTitleAlign(tview.AlignLeft).
		SetBorderColor(tcell.GetColor("green"))

	s.logs.SetChangedFunc(func() {
		s.app.QueueUpdateDraw(func() {
			s.logs.ScrollToEnd()
		})
	})

	fmt.Fprintf(s.logs, "[#33FF33]%s[#D4FFD4]\n", Banner)
	fmt.Fprintf(s.logs, "[#66FF66]Honeygo %s started. Type /help for commands.[#D4FFD4]\n\n", Version)

	// Input Field
	s.input = tview.NewInputField().
		SetLabel(" honeygo> ").
		SetLabelColor(tcell.GetColor("green")).
		SetFieldBackgroundColor(tcell.GetColor("black")).
		SetFieldTextColor(tcell.GetColor("white"))

	s.input.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyUp:
			if len(s.history) > 0 {
				if s.histIdx == -1 {
					s.histIdx = len(s.history) - 1
				} else if s.histIdx > 0 {
					s.histIdx--
				}
				s.input.SetText(s.history[s.histIdx])
			}
			return nil
		case tcell.KeyDown:
			if s.histIdx != -1 {
				if s.histIdx < len(s.history)-1 {
					s.histIdx++
					s.input.SetText(s.history[s.histIdx])
				} else {
					s.histIdx = -1
					s.input.SetText("")
				}
			}
			return nil
		}
		return event
	})

	s.input.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEnter {
			text := s.input.GetText()
			if text == "" {
				return
			}
			s.input.SetText("")
			s.history = append(s.history, text)
			s.histIdx = -1

			if strings.HasPrefix(text, "/") {
				if s.handleCommand(text) {
					s.app.Stop()
				}
			} else {
				fmt.Fprintf(s.logs, "[red][!] Unknown command: %s[white]\n", tview.Escape(text))
			}
		}
	})

	// Layout
	flex := tview.NewFlex().
		SetDirection(tview.FlexRow).
		AddItem(s.logs, 0, 1, false).
		AddItem(s.input, 1, 1, true)

	s.app.SetRoot(flex, true).SetFocus(s.input)

	return s
}

func (s *Shell) Run() error {
	// Check if stdin is a real TTY terminal
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		// Not a TTY, just wait for context or exit
		<-s.manager.Ctx().Done()
		return nil
	}

	// Propagate UI logger ONLY IF RUNNING TUI
	infoWriter := syslog.NewInfoWriter(s.logs)
	s.manager.SetLogger(infoWriter)
	misp.SetLogger(infoWriter)
	css.SetLogger(s.logs)
	syslog.AddWriter(s.logs)
	if s.manager.IsoEngine != nil {
		s.manager.IsoEngine.SetLogger(infoWriter)
	}

	return s.app.Run()
}

func (s *Shell) handleCommand(input string) bool {
	parts := strings.Split(input, " ")
	command := parts[0]

	switch command {
	case "/info", "/verbose", "/toggle":
		if len(parts) > 1 {
			arg := strings.ToLower(parts[1])
			switch arg {
			case "on", "enable", "true", "1":
				syslog.SetInfoLogging(true)
				fmt.Fprintf(s.logs, "[green][+] Informational messages ENABLED (events, errors, and connected sensors streaming live)[white]\n")
			case "off", "disable", "false", "0":
				syslog.SetInfoLogging(false)
				fmt.Fprintf(s.logs, "[yellow][-] Informational messages DISABLED (routine background events and errors suppressed; first-time sensor connections will still be shown)[white]\n")
			case "status":
				if syslog.IsInfoLoggingEnabled() {
					fmt.Fprintf(s.logs, "[cyan]Informational messages: [green]ENABLED[white] (events, errors, and connected sensors streaming live)\n")
				} else {
					fmt.Fprintf(s.logs, "[cyan]Informational messages: [yellow]DISABLED[white] (routine background events and errors suppressed; first-time sensor connections will still be shown)\n")
				}
			default:
				fmt.Fprintf(s.logs, "[yellow]Usage: /info [on|off|status][white]\n")
			}
		} else {
			newState := syslog.ToggleInfoLogging()
			if newState {
				fmt.Fprintf(s.logs, "[green][+] Informational messages ENABLED (events, errors, and connected sensors streaming live)[white]\n")
			} else {
				fmt.Fprintf(s.logs, "[yellow][-] Informational messages DISABLED (routine background events and errors suppressed; first-time sensor connections will still be shown)[white]\n")
			}
		}

	case "/help":
		helpText := RenderHelp(parts[1:])
		fmt.Fprint(s.logs, helpText)

	case "/syslog":
		catFilter := ""
		limit := 50
		if len(parts) > 1 {
			catFilter = parts[1]
		}
		if len(parts) > 2 {
			if parsed, err := strconv.Atoi(parts[2]); err == nil && parsed > 0 {
				limit = parsed
			}
		}
		entries := syslog.GetEntries(catFilter, "ALL", limit)
		fmt.Fprintf(s.logs, "[cyan]System & Troubleshooting Audit Logs (%d entries):[white]\n", len(entries))
		for _, e := range entries {
			color := "white"
			switch e.Level {
			case syslog.LevelWarn:
				color = "yellow"
			case syslog.LevelError:
				color = "red"
			default:
				color = "cyan"
			}
			fmt.Fprintf(s.logs, "  [%s] [%s][%s][white] [%s] %s\n",
				e.Timestamp.Format("15:04:05"), color, tview.Escape(string(e.Category)), tview.Escape(string(e.Level)), tview.Escape(e.Message))
		}

	case "/services":
		if len(parts) > 1 && strings.TrimSpace(parts[1]) != "" {
			fmt.Fprint(s.logs, RenderHelp([]string{"services", parts[1]}))
			break
		}
		protocols := s.manager.GetAvailableProtocols()
		statusMap := s.manager.GetStatus()
		fmt.Fprintf(s.logs, "[cyan]Available Service Types & Isolation Status:[white]\n")
		for _, p := range protocols {
			isoDesc := ""
			switch p {
			case "modbus", "s7comm":
				isoDesc = "[green]Isolated[white] (Mandatory Container Sandbox)"
			case "ssh", "telnet", "vnc":
				isoDesc = "[yellow]Supports Isolation[white] (Container Sandbox or Native Mock)"
			case "web":
				isoDesc = "[red]Not Isolated[white] (Native Profile-based HTTP Honeypot)"
			case "css":
				isoDesc = "[red]Not Isolated[white] (Native Central Storage Server & WebUI)"
			default:
				isoDesc = "[white]Not Isolated"
			}

			var activeInstances []string
			for port, st := range statusMap {
				if st.Protocol == p && st.Status == "Running" {
					isoStr := "Not Isolated"
					if st.Isolated {
						isoStr = "Isolated"
					}
					activeInstances = append(activeInstances, fmt.Sprintf("Port %d: %s", port, isoStr))
				}
			}
			if p == "css" && s.manager.AnalyticsSrv != nil {
				activeInstances = append(activeInstances, fmt.Sprintf("Port %d: Not Isolated", s.manager.AnalyticsSrv.Port()))
			}

			if len(activeInstances) > 0 {
				fmt.Fprintf(s.logs, "  - %-8s : %s | Active: %s\n", p, isoDesc, strings.Join(activeInstances, ", "))
			} else {
				fmt.Fprintf(s.logs, "  - %-8s : %s\n", p, isoDesc)
			}
		}

	case "/webprofile":
		if len(parts) < 2 {
			fmt.Fprintf(s.logs, "[yellow]Current active web profile: %s[white]\n", s.manager.DefaultWebProfile)
			fmt.Fprintf(s.logs, "[yellow]Available profiles:[white]\n")
			for _, p := range s.manager.GetAvailableWebProfiles() {
				fmt.Fprintf(s.logs, "  - %s\n", p)
			}
			fmt.Fprintf(s.logs, "[yellow]Syntax: /webprofile <profile|path>[white]\n")
			break
		}
		profile := strings.Join(parts[1:], " ")
		if err := s.manager.SetWebProfile(profile); err != nil {
			fmt.Fprintf(s.logs, "[red][!] Error: %v[white]\n", err)
			break
		}
		fmt.Fprintf(s.logs, "[green][+] Active web profile set to: %s (dynamically updated for any running web services)[white]\n", profile)

	case "/modbusprofile":
		if len(parts) < 2 {
			fmt.Fprintf(s.logs, "[cyan]Active Modbus PLC profile:[white] %s\n", s.manager.DefaultModbusProfile)
			fmt.Fprintf(s.logs, "[yellow]Available profiles:[white]\n")
			fmt.Fprintf(s.logs, "  - schneider    : Schneider Electric Modicon M221 PLC v2.10 (Default)\n")
			fmt.Fprintf(s.logs, "  - common-q     : Westinghouse Common Q AC160 Nuclear Safety System\n")
			fmt.Fprintf(s.logs, "  - triconex     : Invensys Triconex Tricon 3008 TMR SIL-3 SIS\n")
			fmt.Fprintf(s.logs, "[yellow]Syntax: /modbusprofile <schneider|common-q|triconex>[white]\n")
			break
		}
		profile := strings.Join(parts[1:], " ")
		s.manager.SetModbusProfile(profile)
		fmt.Fprintf(s.logs, "[green][+] Active Modbus PLC profile set to: %s (dynamically updated for any running Modbus services)[white]\n", profile)

	case "/cleardb":
		if err := db.ClearDB(); err != nil {
			fmt.Fprintf(s.logs, "[red][!] Failed to clear database: %v[white]\n", err)
		} else {
			fmt.Fprintf(s.logs, "[yellow][!] Database cleared successfully.[white]\n")
		}

	case "/clear":
		s.logs.Clear()
		s.logs.ScrollTo(0, 0)
		fmt.Fprintf(s.logs, "[yellow]Logs cleared.[white]\n")

	case "/start":
		if len(parts) < 3 {
			fmt.Fprintf(s.logs, "[yellow]Syntax: /start <service> <port> [--profile <profile>] [--isolated] [--ttl <seconds>][white]\n")
			break
		}
		protocol := parts[1]
		var port int
		_, err := fmt.Sscanf(parts[2], "%d", &port)
		if err != nil {
			fmt.Fprintf(s.logs, "[red][!] Invalid port: %s[white]\n", tview.Escape(parts[2]))
			break
		}
		
		isolated := false
		ttl := 0
		customProfile := ""
		for i := 3; i < len(parts); i++ {
			if parts[i] == "--isolated" {
				isolated = true
			} else if strings.HasPrefix(parts[i], "--ttl=") {
				parsedTTL, err := strconv.Atoi(strings.TrimPrefix(parts[i], "--ttl="))
				if err == nil && parsedTTL > 0 {
					ttl = parsedTTL
				}
			} else if parts[i] == "--ttl" && i+1 < len(parts) {
				parsedTTL, err := strconv.Atoi(parts[i+1])
				if err == nil && parsedTTL > 0 {
					ttl = parsedTTL
					i++
				}
			} else if strings.HasPrefix(parts[i], "--profile=") {
				customProfile = strings.TrimPrefix(parts[i], "--profile=")
			} else if parts[i] == "--profile" && i+1 < len(parts) {
				customProfile = parts[i+1]
				i++
			}
		}

		if customProfile != "" {
			if protocol == "modbus" {
				s.manager.SetModbusProfile(customProfile)
			} else if protocol == "web" {
				if err := s.manager.SetWebProfile(customProfile); err != nil {
					fmt.Fprintf(s.logs, "[red][!] Error setting web profile: %v[white]\n", err)
					break
				}
			}
		}

		if err := s.manager.StartService(protocol, port, isolated, ttl); err != nil {
			fmt.Fprintf(s.logs, "[red][!] Error: %v[white]\n", err)
		} else {
			isoStr := ""
			if isolated {
				isoStr = " (isolated)"
			}
			profStr := ""
			if customProfile != "" {
				profStr = fmt.Sprintf(" [Profile: %s]", customProfile)
			}
			appliedTTL := ttl
			if appliedTTL == 0 {
				appliedTTL = 300
			}
			fmt.Fprintf(s.logs, "[green][+] Service %s on port %d started%s%s (TTL: %ds).[white]\n", protocol, port, isoStr, profStr, appliedTTL)
		}

	case "/stop":
		if len(parts) < 2 {
			fmt.Fprintf(s.logs, "[yellow]Syntax: /stop <service> [port][white]\n")
			break
		}
		protocol := parts[1]
		if len(parts) == 2 {
			count := s.manager.StopServiceByProtocol(protocol)
			fmt.Fprintf(s.logs, "[green][-] Stopped %d instances of %s.[white]\n", count, protocol)
		} else {
			var port int
			fmt.Sscanf(parts[2], "%d", &port)
			if err := s.manager.StopService(protocol, port); err != nil {
				fmt.Fprintf(s.logs, "[red][!] Error: %v[white]\n", err)
			} else {
				fmt.Fprintf(s.logs, "[green][-] Service %s on port %d stopped.[white]\n", protocol, port)
			}
		}

	case "/status":
		status := s.manager.GetStatus()
		activeCount := 0
		for _, info := range status {
			if info.Status == "Running" {
				activeCount++
			}
		}
		if s.manager.AnalyticsSrv != nil {
			activeCount++
		}
		if activeCount == 0 {
			fmt.Fprintf(s.logs, "No services are currently running.\n")
		} else {
			fmt.Fprintf(s.logs, "[cyan]Active Running Services:[white]\n")
			for port, info := range status {
				if info.Status == "Running" {
					isoStr := "[yellow][Not Isolated][white]"
					if info.Isolated {
						isoStr = "[green][Isolated][white]"
					}
					fmt.Fprintf(s.logs, "  [green]●[white] [%-8s] Port %d: %s %s\n", info.Protocol, port, info.Status, isoStr)
				}
			}
			if s.manager.AnalyticsSrv != nil {
				proto := "http"
				if s.manager.AnalyticsSrv.IsSSLEnabled() {
					proto = "https"
				}
				fmt.Fprintf(s.logs, "  [green]●[white] [analytics] Port %d: Running [yellow][Not Isolated][white] (Dashboard: %s://localhost:%d)\n", s.manager.AnalyticsSrv.Port(), proto, s.manager.AnalyticsSrv.Port())
			}
		}

	case "/logs":
		if len(parts) > 1 {
			subCmd := strings.ToLower(parts[1])
			switch subCmd {
			case "web":
				limit := 10
				if len(parts) > 2 {
					if l, err := strconv.Atoi(parts[2]); err == nil && l > 0 {
						limit = l
					}
				}
				var attempts []db.Attempt
				db.DB.Where("protocol = ?", "web").Order("created_at desc").Limit(limit).Find(&attempts)
				if len(attempts) == 0 {
					fmt.Fprintf(s.logs, "No web logs yet.\n")
				} else {
					fmt.Fprintf(s.logs, "[cyan]Recent Web Requests (last %d):[white]\n", len(attempts))
					for _, a := range attempts {
						escapedRaw := tview.Escape(a.RawData)
						fmt.Fprintf(s.logs, "  [yellow]-- [ID: %d] Request from %s on port %d at %s (%d bytes) --[white]\n%s\n\n",
							a.ID, tview.Escape(a.RemoteIP), a.Port, a.CreatedAt.Local().Format("15:04:05 MST"), len(a.RawData), escapedRaw)
					}
					fmt.Fprintf(s.logs, "[grey]Tip: Type '/logs req <id> [raw|hex|ascii|base64]' to inspect or '/logs download <id> <filepath>' to save.[white]\n\n")
				}
			case "req", "request", "view", "inspect":
				if len(parts) < 3 {
					fmt.Fprintf(s.logs, "[yellow]Syntax: /logs req <id> [raw|hex|ascii|base64][white]\n")
					break
				}
				id64, err := strconv.ParseUint(parts[2], 10, 64)
				if err != nil || id64 == 0 {
					fmt.Fprintf(s.logs, "[red][!] Invalid attempt ID: %s[white]\n", tview.Escape(parts[2]))
					break
				}
				attempt, err := db.GetAttemptByID(uint(id64))
				if err != nil {
					fmt.Fprintf(s.logs, "[red][!] Request #%d not found: %v[white]\n", id64, err)
					break
				}
				fmtOpt := "raw"
				if len(parts) > 3 {
					fmtOpt = strings.ToLower(parts[3])
				}
				rawBytes := []byte(attempt.RawData)
				fmt.Fprintf(s.logs, "[cyan]================================================================================[white]\n")
				fmt.Fprintf(s.logs, "[green][+] Request #%d Details[white]\n", attempt.ID)
				fmt.Fprintf(s.logs, "  Timestamp: %s\n", attempt.CreatedAt.Local().Format("2006-01-02 15:04:05 MST"))
				fmt.Fprintf(s.logs, "  Protocol:  %s | Sensor: %s\n", tview.Escape(attempt.Protocol), tview.Escape(attempt.SensorID))
				fmt.Fprintf(s.logs, "  Remote IP: %s | Port: %d\n", tview.Escape(attempt.RemoteIP), attempt.Port)
				if attempt.CountryCode != "" || attempt.ASN != "" {
					fmt.Fprintf(s.logs, "  Origin:    %s (%s) | ASN: %s %s\n", tview.Escape(attempt.CountryName), tview.Escape(attempt.CountryCode), tview.Escape(attempt.ASN), tview.Escape(attempt.ASName))
				}
				fmt.Fprintf(s.logs, "  Size:      %d bytes\n", len(rawBytes))
				fmt.Fprintf(s.logs, "[cyan]--------------------------------- Payload (%s) ---------------------------------[white]\n", fmtOpt)

				switch fmtOpt {
				case "hex", "hexdump":
					fmt.Fprintf(s.logs, "%s\n", tview.Escape(db.FormatHexDump(rawBytes)))
				case "rawhex":
					fmt.Fprintf(s.logs, "%s\n", tview.Escape(db.FormatRawHex(rawBytes)))
				case "ascii":
					fmt.Fprintf(s.logs, "%s\n", tview.Escape(db.FormatASCII(rawBytes)))
				case "base64", "b64":
					fmt.Fprintf(s.logs, "%s\n", tview.Escape(db.FormatBase64(rawBytes)))
				default: // raw
					fmt.Fprintf(s.logs, "%s\n", tview.Escape(attempt.RawData))
				}
				fmt.Fprintf(s.logs, "[cyan]================================================================================[white]\n\n")

			case "download", "save":
				if len(parts) < 4 {
					fmt.Fprintf(s.logs, "[yellow]Syntax: /logs download <id> <filepath> [raw|hex|ascii|base64][white]\n")
					break
				}
				id64, err := strconv.ParseUint(parts[2], 10, 64)
				if err != nil || id64 == 0 {
					fmt.Fprintf(s.logs, "[red][!] Invalid attempt ID: %s[white]\n", tview.Escape(parts[2]))
					break
				}
				attempt, err := db.GetAttemptByID(uint(id64))
				if err != nil {
					fmt.Fprintf(s.logs, "[red][!] Request #%d not found: %v[white]\n", id64, err)
					break
				}
				filepath := parts[3]
				fmtOpt := "raw"
				if len(parts) > 4 {
					fmtOpt = strings.ToLower(parts[4])
				}
				rawBytes := []byte(attempt.RawData)
				var outBytes []byte
				switch fmtOpt {
				case "hex", "hexdump":
					outBytes = []byte(db.FormatHexDump(rawBytes))
				case "rawhex":
					outBytes = []byte(db.FormatRawHex(rawBytes))
				case "ascii":
					outBytes = []byte(db.FormatASCII(rawBytes))
				case "base64", "b64":
					outBytes = []byte(db.FormatBase64(rawBytes))
				default: // raw
					outBytes = rawBytes
				}
				err = os.WriteFile(filepath, outBytes, 0644)
				if err != nil {
					fmt.Fprintf(s.logs, "[red][!] Failed to save request #%d to %s: %v[white]\n", attempt.ID, tview.Escape(filepath), err)
				} else {
					fmt.Fprintf(s.logs, "[green][+] Successfully saved request #%d (%d bytes, format: %s) to %s[white]\n", attempt.ID, len(outBytes), fmtOpt, tview.Escape(filepath))
				}

			case "export":
				if len(parts) < 3 {
					fmt.Fprintf(s.logs, "[yellow]Syntax: /logs export <filepath> [service_type] [format]\nServices: ssh, telnet, web, vnc, modbus, s7comm, all\nFormats:  text, raw, hex, ascii, base64, json[white]\n")
					break
				}

				serviceType := "all"
				format := "text"
				filepath := ""

				remaining := parts[2:]
				validFormats := map[string]bool{
					"text": true, "raw": true, "bin": true, "hex": true,
					"ascii": true, "base64": true, "b64": true, "json": true,
				}
				validServices := map[string]bool{
					"ssh": true, "telnet": true, "web": true, "vnc": true,
					"modbus": true, "s7comm": true, "all": true,
				}

				// Check if last argument is a format
				if len(remaining) >= 2 && validFormats[strings.ToLower(remaining[len(remaining)-1])] {
					format = strings.ToLower(remaining[len(remaining)-1])
					remaining = remaining[:len(remaining)-1]
				}

				// Check if current last argument is a service
				if len(remaining) >= 2 && validServices[strings.ToLower(remaining[len(remaining)-1])] {
					serviceType = strings.ToLower(remaining[len(remaining)-1])
					remaining = remaining[:len(remaining)-1]
				}

				filepath = strings.Join(remaining, " ")
				if filepath == "" {
					fmt.Fprintf(s.logs, "[yellow]Syntax: /logs export <filepath> [service_type] [format][white]\n")
					break
				}

				var attempts []db.Attempt
				var queryErr error
				if serviceType == "all" {
					queryErr = db.DB.Order("created_at asc").Find(&attempts).Error
				} else {
					queryErr = db.DB.Where("protocol = ?", serviceType).Order("created_at asc").Find(&attempts).Error
				}

				if queryErr != nil {
					fmt.Fprintf(s.logs, "[red][!] Database query failed: %v[white]\n", queryErr)
					break
				}

				var exportData []byte
				switch format {
				case "raw", "bin":
					var sb strings.Builder
					for _, a := range attempts {
						sb.WriteString(fmt.Sprintf("### ATTEMPT_ID: %d | PROTOCOL: %s | SENSOR: %s | REMOTE_IP: %s | PORT: %d | TIME: %s ###\n",
							a.ID, a.Protocol, a.SensorID, a.RemoteIP, a.Port, a.CreatedAt.UTC().Format(time.RFC3339)))
						sb.WriteString(a.RawData)
						sb.WriteString("\n\n")
					}
					exportData = []byte(sb.String())
				case "hex":
					var sb strings.Builder
					for _, a := range attempts {
						rawBytes := []byte(a.RawData)
						sb.WriteString(fmt.Sprintf("================================================================================\n"))
						sb.WriteString(fmt.Sprintf("Attempt ID:   %d\n", a.ID))
						sb.WriteString(fmt.Sprintf("Timestamp:    %s\n", a.CreatedAt.Local().Format("2006-01-02 15:04:05 MST")))
						sb.WriteString(fmt.Sprintf("Protocol:     %s | Sensor: %s\n", a.Protocol, a.SensorID))
						sb.WriteString(fmt.Sprintf("Remote IP:    %s:%d\n", a.RemoteIP, a.Port))
						sb.WriteString(fmt.Sprintf("Raw Hex:      %s\n", db.FormatRawHex(rawBytes)))
						sb.WriteString(fmt.Sprintf("Payload Size: %d bytes\n", len(rawBytes)))
						sb.WriteString(fmt.Sprintf("--- HEX DUMP ---\n"))
						sb.WriteString(db.FormatHexDump(rawBytes))
						sb.WriteString(fmt.Sprintf("================================================================================\n\n"))
					}
					exportData = []byte(sb.String())
				case "ascii":
					var sb strings.Builder
					for _, a := range attempts {
						rawBytes := []byte(a.RawData)
						sb.WriteString(fmt.Sprintf("================================================================================\n"))
						sb.WriteString(fmt.Sprintf("Attempt ID:   %d\n", a.ID))
						sb.WriteString(fmt.Sprintf("Timestamp:    %s\n", a.CreatedAt.Local().Format("2006-01-02 15:04:05 MST")))
						sb.WriteString(fmt.Sprintf("Protocol:     %s | Sensor: %s\n", a.Protocol, a.SensorID))
						sb.WriteString(fmt.Sprintf("Remote IP:    %s:%d\n", a.RemoteIP, a.Port))
						sb.WriteString(fmt.Sprintf("Payload Size: %d bytes\n", len(rawBytes)))
						sb.WriteString(fmt.Sprintf("--- SAFE ASCII PAYLOAD ---\n"))
						sb.WriteString(db.FormatASCII(rawBytes))
						sb.WriteString(fmt.Sprintf("\n================================================================================\n\n"))
					}
					exportData = []byte(sb.String())
				case "base64", "b64":
					var sb strings.Builder
					for _, a := range attempts {
						rawBytes := []byte(a.RawData)
						sb.WriteString(fmt.Sprintf("================================================================================\n"))
						sb.WriteString(fmt.Sprintf("Attempt ID:   %d\n", a.ID))
						sb.WriteString(fmt.Sprintf("Timestamp:    %s\n", a.CreatedAt.Local().Format("2006-01-02 15:04:05 MST")))
						sb.WriteString(fmt.Sprintf("Protocol:     %s | Sensor: %s\n", a.Protocol, a.SensorID))
						sb.WriteString(fmt.Sprintf("Remote IP:    %s:%d\n", a.RemoteIP, a.Port))
						sb.WriteString(fmt.Sprintf("Base64 Payload:\n%s\n", db.FormatBase64(rawBytes)))
						sb.WriteString(fmt.Sprintf("================================================================================\n\n"))
					}
					exportData = []byte(sb.String())
				case "json":
					type CLIJSONItem struct {
						ID           uint      `json:"id"`
						CreatedAt    time.Time `json:"created_at"`
						SensorID     string    `json:"sensor_id"`
						Protocol     string    `json:"protocol"`
						RemoteIP     string    `json:"remote_ip"`
						Port         int       `json:"port"`
						RawHex       string    `json:"raw_hex"`
						RawBase64    string    `json:"raw_base64"`
						ASCIIEscaped string    `json:"ascii_escaped"`
						HexDump      string    `json:"hexdump"`
						SizeBytes    int       `json:"size_bytes"`
					}
					items := make([]CLIJSONItem, 0, len(attempts))
					for _, a := range attempts {
						rawBytes := []byte(a.RawData)
						items = append(items, CLIJSONItem{
							ID:           a.ID,
							CreatedAt:    a.CreatedAt,
							SensorID:     a.SensorID,
							Protocol:     a.Protocol,
							RemoteIP:     a.RemoteIP,
							Port:         a.Port,
							RawHex:       db.FormatRawHex(rawBytes),
							RawBase64:    db.FormatBase64(rawBytes),
							ASCIIEscaped: db.FormatASCII(rawBytes),
							HexDump:      db.FormatHexDump(rawBytes),
							SizeBytes:    len(rawBytes),
						})
					}
					exportData, _ = json.MarshalIndent(items, "", "  ")
				default: // text
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
					exportData = []byte(sb.String())
				}

				err := os.WriteFile(filepath, exportData, 0644)
				if err != nil {
					fmt.Fprintf(s.logs, "[red][!] Failed to export logs to %s: %v[white]\n", tview.Escape(filepath), err)
				} else {
					fmt.Fprintf(s.logs, "[green][+] Successfully exported %d attempts (%s, format: %s) to %s[white]\n", len(attempts), serviceType, format, tview.Escape(filepath))
				}
			default:
				fmt.Fprintf(s.logs, "[red][!] Unknown /logs option: %s. Use '/logs', '/logs web [limit]', '/logs req <id> [fmt]', '/logs download <id> <fp> [fmt]', or '/logs export <fp> [svc] [fmt]'.[white]\n", tview.Escape(subCmd))
			}
			break
		}

		var attempts []db.Attempt
		db.DB.Order("created_at desc").Limit(10).Find(&attempts)
		if len(attempts) == 0 {
			fmt.Fprintf(s.logs, "No logs yet.\n")
		} else {
			fmt.Fprintf(s.logs, "[cyan]Recent Logs:[white]\n")
			for _, a := range attempts {
				fmt.Fprintf(s.logs, "  [%s] %s connection from %s\n", a.CreatedAt.Local().Format("2006-01-02 15:04:05 MST"), tview.Escape(a.Protocol), tview.Escape(a.RemoteIP))
			}
		}

	case "/creds":
		var creds []db.Credential
		db.DB.Order("created_at desc").Limit(10).Find(&creds)
		if len(creds) == 0 {
			fmt.Fprintf(s.logs, "No credentials captured yet.\n")
		} else {
			fmt.Fprintf(s.logs, "[yellow]Captured Credentials:[white]\n")
			for _, c := range creds {
				fmt.Fprintf(s.logs, "  [%s] %s: %s:%s from %s\n", c.CreatedAt.Local().Format("2006-01-02 15:04:05 MST"), tview.Escape(c.Protocol), tview.Escape(c.Username), tview.Escape(c.Password), tview.Escape(c.RemoteIP))
			}
		}

	case "/analytics":
		if len(parts) < 2 {
			if s.manager.AnalyticsSrv != nil {
				fmt.Fprintf(s.logs, "[yellow]Analytics dashboard is running on port %d: http://localhost:%d[white]\n", s.manager.AnalyticsSrv.Port(), s.manager.AnalyticsSrv.Port())
			} else {
				fmt.Fprintf(s.logs, "[yellow]Analytics dashboard is stopped.[white]\n")
			}
			fmt.Fprintf(s.logs, "[yellow]Syntax: /analytics <start|stop> [port][white]\n")
			break
		}
		action := parts[1]
		switch action {
		case "start":
			port := 8090
			useSSL := false
			for i := 2; i < len(parts); i++ {
				if parts[i] == "--ssl" || parts[i] == "--https" {
					useSSL = true
				} else if p, err := strconv.Atoi(parts[i]); err == nil && p > 0 {
					port = p
				}
			}
			s.manager.SetSSL(useSSL)
			if err := s.manager.StartAnalytics(port); err != nil {
				fmt.Fprintf(s.logs, "[red][!] Error starting analytics dashboard: %v[white]\n", err)
			} else {
				proto := "https"
				if !useSSL {
					proto = "http"
				}
				fmt.Fprintf(s.logs, "[green][+] Analytics dashboard (%s) started on port %d: %s://localhost:%d[white]\n", strings.ToUpper(proto), port, proto, port)
			}
		case "stop":
			if err := s.manager.StopAnalytics(); err != nil {
				fmt.Fprintf(s.logs, "[red][!] Error stopping analytics dashboard: %v[white]\n", err)
			} else {
				fmt.Fprintf(s.logs, "[green][-] Analytics dashboard stopped.[white]\n")
			}
		default:
			fmt.Fprintf(s.logs, "[red][!] Unknown analytics action: %s. Use 'start' or 'stop'.[white]\n", action)
		}

	case "/telegram":
		if len(parts) == 2 && parts[1] == "off" {
			alerting.Token = ""
			alerting.ChatID = ""
			fmt.Fprintf(s.logs, "[yellow][-] Telegram alerts disabled.[white]\n")
		} else if len(parts) >= 3 {
			alerting.Token = parts[1]
			alerting.ChatID = parts[2]
			fmt.Fprintf(s.logs, "[green][+] Telegram alerts enabled.[white]\n")
		} else {
			fmt.Fprintf(s.logs, "[yellow]Syntax: /telegram <token> <chat_id> OR /telegram off[white]\n")
		}

	case "/misp":
		if len(parts) == 1 {
			url, key, skipVerify := misp.GetConfig()
			if !misp.IsEnabled() {
				if url != "" {
					maskedKey := misp.MaskAPIKey(key)
					fmt.Fprintf(s.logs, "[yellow]MISP integration is currently disabled (Saved Server: %s, Key: %s, Skip SSL: %t).[white]\n", url, maskedKey, skipVerify)
				} else {
					fmt.Fprintf(s.logs, "[yellow]MISP integration is currently disabled (not configured).[white]\n")
				}
			} else {
				maskedKey := misp.MaskAPIKey(key)
				fmt.Fprintf(s.logs, "[cyan]MISP Configuration (Active):[white]\n")
				fmt.Fprintf(s.logs, "  URL:                   %s\n", url)
				fmt.Fprintf(s.logs, "  API Key:               %s\n", maskedKey)
				fmt.Fprintf(s.logs, "  Skip SSL Verification: %t\n", skipVerify)
			}
		} else if len(parts) == 2 && (parts[1] == "off" || parts[1] == "disable") {
			misp.Disable()
			fmt.Fprintf(s.logs, "[yellow][-] MISP integration disabled (settings preserved).[white]\n")
		} else if len(parts) >= 3 {
			url := parts[1]
			key := parts[2]
			skipVerify := false
			for i := 3; i < len(parts); i++ {
				if parts[i] == "--skip-verify" {
					skipVerify = true
				}
			}
			misp.Init(url, key, skipVerify, s.logs)
			fmt.Fprintf(s.logs, "[green][+] MISP integration configured and enabled.[white]\n")
		} else {
			fmt.Fprintf(s.logs, "[yellow]Syntax: /misp <url> <key> [--skip-verify] OR /misp off[white]\n")
		}

	case "/css":
		if len(parts) == 1 {
			cfg := css.GetConfig()
			fmt.Fprintf(s.logs, "[cyan]Central Storage Server (CSS) Configuration:[white]\n")
			fmt.Fprintf(s.logs, "  Server Mode:         %t (Port: %d)\n", cfg.ServerEnabled, cfg.ServerPort)
			fmt.Fprintf(s.logs, "  Token Auth Enabled:  %t\n", cfg.TokenAuthEnabled)
			if cfg.AuthToken != "" {
				maskedToken := cfg.AuthToken
				if len(maskedToken) > 6 {
					maskedToken = maskedToken[:3] + "..." + maskedToken[len(maskedToken)-3:]
				}
				fmt.Fprintf(s.logs, "  Auth Token:          %s\n", maskedToken)
			} else {
				fmt.Fprintf(s.logs, "  Auth Token:          None\n")
			}
			fmt.Fprintf(s.logs, "  Sensor Mode Active:  %t\n", css.IsSensorMode())
			if cfg.CSSURL != "" {
				fmt.Fprintf(s.logs, "  CSS Server URL:      %s\n", cfg.CSSURL)
				fmt.Fprintf(s.logs, "  Sensor ID:           %s\n", css.GetSensorID())
			}
			fmt.Fprintf(s.logs, "  Sensor Checkin TTL:  %ds\n", cfg.SensorCheckinTTL)
			if cfg.CartoAPIKey != "" {
				maskedKey := cfg.CartoAPIKey
				if len(maskedKey) > 8 {
					maskedKey = maskedKey[:4] + "..." + maskedKey[len(maskedKey)-4:]
				}
				fmt.Fprintf(s.logs, "  CARTO Map API Key:   %s\n", maskedKey)
			} else {
				fmt.Fprintf(s.logs, "  CARTO Map API Key:   None\n")
			}
			break
		}

		subCmd := parts[1]
		switch subCmd {
		case "server":
			if len(parts) >= 3 && parts[2] == "start" {
				port := 8090
				token := ""
				tokenAuth := false
				useSSL := false
				for i := 3; i < len(parts); i++ {
					if strings.HasPrefix(parts[i], "--port=") {
						p, err := strconv.Atoi(strings.TrimPrefix(parts[i], "--port="))
						if err == nil {
							port = p
						}
					} else if parts[i] == "--token" && i+1 < len(parts) {
						token = parts[i+1]
						tokenAuth = true
						i++
					} else if parts[i] == "--ssl" || parts[i] == "--https" {
						useSSL = true
					} else if !strings.HasPrefix(parts[i], "-") {
						p, err := strconv.Atoi(parts[i])
						if err == nil {
							port = p
						}
					}
				}
				s.manager.SetSSL(useSSL)
				if err := s.manager.StartAnalytics(port); err != nil {
					fmt.Fprintf(s.logs, "[red][!] Failed to start CSS server: %v[white]\n", err)
				} else {
					css.SetServerConfig(true, port, tokenAuth, token, useSSL)
					proto := "https"
					if !useSSL {
						proto = "http"
					}
					fmt.Fprintf(s.logs, "[green][+] CSS Server (%s) started on port %d: %s://localhost:%d[white]\n", strings.ToUpper(proto), port, proto, port)
				}
			} else if len(parts) >= 3 && parts[2] == "stop" {
				if err := s.manager.StopAnalytics(); err != nil {
					fmt.Fprintf(s.logs, "[red][!] Error stopping CSS server: %v[white]\n", err)
				} else {
					cfg := css.GetConfig()
					cfg.ServerEnabled = false
					css.UpdateConfig(cfg)
					fmt.Fprintf(s.logs, "[green][-] CSS Server stopped.[white]\n")
				}
			} else {
				fmt.Fprintf(s.logs, "[yellow]Syntax: /css server <start|stop> [port] [--token <tok>] [--ssl][white]\n")
			}

		case "ttl", "interval":
			if len(parts) >= 3 {
				ttl, err := strconv.Atoi(parts[2])
				if err != nil || ttl <= 0 {
					fmt.Fprintf(s.logs, "[red][!] Invalid TTL: must be a positive number of seconds[white]\n")
					break
				}
				css.SetSensorCheckinTTL(ttl)
				fmt.Fprintf(s.logs, "[green][+] Sensor checkin TTL set to %ds[white]\n", ttl)
			} else {
				ttl := css.GetSensorCheckinTTL()
				fmt.Fprintf(s.logs, "[cyan]Current sensor checkin TTL: [white]%ds\n", ttl)
				fmt.Fprintf(s.logs, "[yellow]Usage: /css ttl <seconds>[white]\n")
			}

		case "connect":
			if len(parts) < 3 {
				fmt.Fprintf(s.logs, "[yellow]Syntax: /css connect <url> [--token <token>] [--sensor-id <id>] [--ttl <seconds>] [-k][white]\n")
				break
			}
			cssURL := parts[2]
			token := ""
			sensorID := css.GetSensorID()
			checkinTTL := css.GetSensorCheckinTTL()
			skipVerify := false
			for i := 3; i < len(parts); i++ {
				if parts[i] == "--token" && i+1 < len(parts) {
					token = parts[i+1]
					i++
				} else if parts[i] == "--sensor-id" && i+1 < len(parts) {
					sensorID = parts[i+1]
					i++
				} else if (parts[i] == "--ttl" || parts[i] == "--interval") && i+1 < len(parts) {
					if t, err := strconv.Atoi(parts[i+1]); err == nil && t > 0 {
						checkinTTL = t
					}
					i++
				} else if parts[i] == "-k" || parts[i] == "--skip-verify" || parts[i] == "--insecure" {
					skipVerify = true
				}
			}
			css.SetSensorCheckinTTL(checkinTTL)
			css.SetSensorSkipVerify(skipVerify)
			if err := css.ConnectSensorWithVerify(cssURL, token, sensorID, checkinTTL, skipVerify); err != nil {
				fmt.Fprintf(s.logs, "[red][!] Connection failed: %v[white]\n", err)
			} else {
				verifyMsg := ""
				if skipVerify {
					verifyMsg = ", self-signed SSL allowed"
				}
				fmt.Fprintf(s.logs, "[green][+] Connected to CSS at %s as sensor '%s' (TTL: %ds%s, server acknowledged, local DB, MISP, and Telegram disabled).[white]\n", cssURL, sensorID, checkinTTL, verifyMsg)
			}

		case "disconnect", "off":
			css.DisconnectSensor()
			fmt.Fprintf(s.logs, "[yellow][-] Disconnected from CSS. Reverted to local storage and alert dispatching.[white]\n")

		case "token":
			if len(parts) >= 3 && parts[2] == "off" {
				cfg := css.GetConfig()
				cfg.TokenAuthEnabled = false
				css.UpdateConfig(cfg)
				fmt.Fprintf(s.logs, "[yellow][-] CSS token authentication disabled.[white]\n")
			} else if len(parts) >= 3 {
				token := parts[2]
				cfg := css.GetConfig()
				cfg.TokenAuthEnabled = true
				cfg.AuthToken = token
				css.UpdateConfig(cfg)
				fmt.Fprintf(s.logs, "[green][+] CSS token authentication enabled.[white]\n")
			} else {
				fmt.Fprintf(s.logs, "[yellow]Syntax: /css token <token> OR /css token off[white]\n")
			}

		case "carto", "cartomap":
			if len(parts) >= 3 && (parts[2] == "off" || parts[2] == "none" || parts[2] == "clear") {
				css.SetCartoAPIKey("")
				fmt.Fprintf(s.logs, "[yellow][-] CARTO Map API key cleared.[white]\n")
			} else if len(parts) >= 3 {
				key := strings.TrimSpace(parts[2])
				css.SetCartoAPIKey(key)
				maskedKey := key
				if len(maskedKey) > 8 {
					maskedKey = maskedKey[:4] + "..." + maskedKey[len(maskedKey)-4:]
				}
				fmt.Fprintf(s.logs, "[green][+] CARTO Map API key configured: %s[white]\n", maskedKey)
			} else {
				fmt.Fprintf(s.logs, "[yellow]Syntax: /css carto <api_key> OR /css carto off[white]\n")
			}

		case "name", "rename":
			if len(parts) < 4 {
				fmt.Fprintf(s.logs, "[yellow]Syntax: /css name <sensor_id> <display_name>[white]\n")
				break
			}
			sensorID := parts[2]
			newName := strings.Join(parts[3:], " ")
			if err := db.UpdateSensorDisplayName(sensorID, newName); err != nil {
				fmt.Fprintf(s.logs, "[red][!] Failed to update sensor display name: %v[white]\n", err)
			} else {
				fmt.Fprintf(s.logs, "[green][+] Updated display name for sensor '%s' to '%s'[white]\n", sensorID, newName)
			}

		case "sensors":
			sensors, err := db.GetSensorsList()
			if err != nil || len(sensors) == 0 {
				fmt.Fprintf(s.logs, "[yellow]No remote sensors currently connected or registered.[white]\n")
				break
			}
			activeCount := 0
			for _, sNode := range sensors {
				if sNode.Status == "Active" || sNode.Status == "Online" {
					activeCount++
				}
			}
			fmt.Fprintf(s.logs, "[cyan]Honeypot Sensors (%d total, %d active):[white]\n", len(sensors), activeCount)
			fmt.Fprintf(s.logs, "  %-22s | %-16s | %-8s | %-6s | %-10s | %-10s | %s\n", "SENSOR ID / NAME", "REMOTE IP", "STATUS", "TTL", "ISOLATION", "EVENTS", "RUNNING SERVICES")
			fmt.Fprintf(s.logs, "  %s\n", strings.Repeat("-", 102))
			for _, sNode := range sensors {
				svcsStr := "None"
				if len(sNode.Services) > 0 {
					var svcParts []string
					for _, svc := range sNode.Services {
						iso := ""
						if svc.Isolated {
							iso = " [sandbox]"
						}
						svcParts = append(svcParts, fmt.Sprintf("%s:%d%s", svc.Protocol, svc.Port, iso))
					}
					svcsStr = strings.Join(svcParts, ", ")
				}
				color := "[green]"
				if sNode.Status == "Idle" {
					color = "[yellow]"
				} else if sNode.Status == "Offline" {
					color = "[red]"
				}
				nameTag := sNode.SensorID
				if sNode.DisplayName != "" {
					nameTag = fmt.Sprintf("%s (%s)", sNode.DisplayName, sNode.SensorID)
				}
				isoTag := "[yellow]Disabled[white]"
				if sNode.Isolation {
					isoTag = "[green]Active[white]"
				}
				ttlVal := sNode.CheckinTTL
				if ttlVal <= 0 {
					ttlVal = 15
				}
				ttlTag := fmt.Sprintf("%ds", ttlVal)
				fmt.Fprintf(s.logs, "  %-22s | %-16s | %s%-8s[white] | %-6s | %-19s | %-10d | %s\n",
					nameTag, sNode.RemoteIP, color, sNode.Status, ttlTag, isoTag, sNode.EventCount, svcsStr)
			}

		case "start":
			if len(parts) < 4 {
				fmt.Fprintf(s.logs, "[yellow]Syntax: /css start <sensor_id> <protocol> [port] [--isolated] [--profile <profile>] [--ttl <seconds>][white]\n")
				break
			}
			sensorID := parts[2]
			protocol := parts[3]
			port := 0
			isolated := false
			profile := ""
			ttl := 0
			for i := 4; i < len(parts); i++ {
				if parts[i] == "--isolated" || parts[i] == "-i" {
					isolated = true
				} else if strings.HasPrefix(parts[i], "--profile=") {
					profile = strings.TrimPrefix(parts[i], "--profile=")
				} else if parts[i] == "--profile" && i+1 < len(parts) {
					profile = parts[i+1]
					i++
				} else if strings.HasPrefix(parts[i], "--ttl=") {
					pTTL, err := strconv.Atoi(strings.TrimPrefix(parts[i], "--ttl="))
					if err == nil {
						ttl = pTTL
					}
				} else if parts[i] == "--ttl" && i+1 < len(parts) {
					pTTL, err := strconv.Atoi(parts[i+1])
					if err == nil {
						ttl = pTTL
						i++
					}
				} else if !strings.HasPrefix(parts[i], "-") {
					pPort, err := strconv.Atoi(parts[i])
					if err == nil {
						port = pPort
					}
				}
			}
			if err := css.ControlSensorService(sensorID, "start", protocol, port, isolated, profile, ttl); err != nil {
				fmt.Fprintf(s.logs, "[red][!] Failed to start service on sensor '%s': %v[white]\n", sensorID, err)
			} else {
				isoStr := ""
				if isolated {
					isoStr = " (isolated)"
				}
				profStr := ""
				if profile != "" {
					profStr = fmt.Sprintf(" [Profile: %s]", profile)
				}
				ttlStr := ""
				if ttl > 0 {
					ttlStr = fmt.Sprintf(" (TTL: %ds)", ttl)
				}
				fmt.Fprintf(s.logs, "[green][+] Service %s start command sent to sensor '%s'%s%s%s.[white]\n", protocol, sensorID, isoStr, profStr, ttlStr)
			}

		case "stop":
			if len(parts) < 4 {
				fmt.Fprintf(s.logs, "[yellow]Syntax: /css stop <sensor_id> <protocol> [port][white]\n")
				break
			}
			sensorID := parts[2]
			protocol := parts[3]
			port := 0
			if len(parts) >= 5 {
				pPort, err := strconv.Atoi(parts[4])
				if err == nil {
					port = pPort
				}
			}
			if err := css.ControlSensorService(sensorID, "stop", protocol, port, false, "", 0); err != nil {
				fmt.Fprintf(s.logs, "[red][!] Failed to stop service on sensor '%s': %v[white]\n", sensorID, err)
			} else {
				fmt.Fprintf(s.logs, "[green][-] Service %s stop command sent to sensor '%s'.[white]\n", protocol, sensorID)
			}

		default:
			fmt.Fprintf(s.logs, "[red][!] Unknown /css subcommand: %s[white]\n", subCmd)
		}

	case "/recon":
		if len(parts) == 1 || (len(parts) == 2 && parts[1] == "status") {
			total, droppers, canaryHits, highRisk := db.GetReconStats()
			autoStatus := "[red]DISABLED[white]"
			if recon.IsAutoReconEnabled() {
				autoStatus = "[green]ENABLED[white]"
			}
			fmt.Fprintf(s.logs, "[cyan]🎯 Secondary Attack Infrastructure & C2 Dropper Recon:[white]\n")
			fmt.Fprintf(s.logs, "  Auto PTR & GeoIP Enrichment:  %s\n", autoStatus)
			fmt.Fprintf(s.logs, "  Tracked Attack Targets:       %d\n", total)
			fmt.Fprintf(s.logs, "  Payload Staging / C2 Hosts:   %d\n", droppers)
			fmt.Fprintf(s.logs, "  Canary Token Hit Targets:     %d\n", canaryHits)
			fmt.Fprintf(s.logs, "  High Risk Targets (Score>=60): %d\n", highRisk)
			fmt.Fprintf(s.logs, "\n[yellow]Usage Commands:[white]\n")
			fmt.Fprintf(s.logs, "  /recon <ip>             - Show passive OSINT profile (PTR, GeoIP, ASN, threat tags)\n")
			fmt.Fprintf(s.logs, "  /recon add <ip> [type] [desc] - Manually track secondary attack infra or canary IP\n")
			fmt.Fprintf(s.logs, "  /recon canary <ip> [tok] - Manually record a canary token hit IP\n")
			fmt.Fprintf(s.logs, "  /recon list [limit]     - List all tracked secondary attack hosts and C2 droppers\n")
			fmt.Fprintf(s.logs, "  /recon auto <on|off>    - Toggle automatic background PTR/GeoIP enrichment\n")
			fmt.Fprintf(s.logs, "  /recon scanall          - Enrich all pending targets with PTR and GeoIP\n")
			break
		}

		subCmd := parts[1]
		switch subCmd {
		case "add":
			if len(parts) < 3 {
				fmt.Fprintf(s.logs, "[yellow]Syntax: /recon add <ip> [canary|c2] [description/context][white]\n")
				break
			}
			targetIP := parts[2]
			sType := "canary_hit"
			ctx := "Manual Secondary Target"
			if len(parts) >= 4 {
				if parts[3] == "canary" || parts[3] == "canary_hit" {
					sType = "canary_hit"
					if len(parts) >= 5 {
						ctx = strings.Join(parts[4:], " ")
					} else {
						ctx = "Manual Canary Token Alert"
					}
				} else if parts[3] == "c2" || parts[3] == "c2_dropper" || parts[3] == "dropper" {
					sType = "c2_dropper"
					if len(parts) >= 5 {
						ctx = strings.Join(parts[4:], " ")
					} else {
						ctx = "Manual C2 Dropper Target"
					}
				} else {
					ctx = strings.Join(parts[3:], " ")
				}
			}
			target, err := recon.AddManualTarget(targetIP, sType, ctx)
			if err != nil {
				fmt.Fprintf(s.logs, "[red][!] Failed to add target: %v[white]\n", err)
				break
			}
			fmt.Fprintf(s.logs, "[green][+] Successfully tracked target %s (%s - %s)[white]\n", tview.Escape(target.IP), tview.Escape(target.SourceType), tview.Escape(ctx))
			fmt.Fprintf(s.logs, "[cyan][*] Queued for PTR and GeoIP enrichment.[white]\n")

		case "canary":
			if len(parts) < 3 {
				fmt.Fprintf(s.logs, "[yellow]Syntax: /recon canary <ip> [token_context][white]\n")
				break
			}
			canaryIP := parts[2]
			ctx := "Manual Canary Token Hit"
			if len(parts) >= 4 {
				ctx = strings.Join(parts[3:], " ")
			}
			target, err := recon.AddManualCanaryHit(canaryIP, ctx)
			if err != nil {
				fmt.Fprintf(s.logs, "[red][!] Failed to add canary hit: %v[white]\n", err)
				break
			}
			fmt.Fprintf(s.logs, "[green][+] Successfully logged canary token hit for IP %s (%s)[white]\n", tview.Escape(target.IP), tview.Escape(ctx))
			fmt.Fprintf(s.logs, "[cyan][*] Queued for PTR and GeoIP enrichment.[white]\n")

		case "auto":
			if len(parts) >= 3 && parts[2] == "off" {
				recon.SetAutoRecon(false)
				fmt.Fprintf(s.logs, "[yellow][-] Automatic background enrichment disabled.[white]\n")
			} else if len(parts) >= 3 && parts[2] == "on" {
				recon.SetAutoRecon(true)
				fmt.Fprintf(s.logs, "[green][+] Automatic background enrichment enabled.[white]\n")
			} else {
				fmt.Fprintf(s.logs, "[yellow]Syntax: /recon auto <on|off>[white]\n")
			}

		case "scanall":
			count := recon.ScanAllPending()
			fmt.Fprintf(s.logs, "[green][+] Queued %d pending targets for PTR and GeoIP enrichment.[white]\n", count)

		case "list":
			limit := 25
			if len(parts) >= 3 {
				if l, err := strconv.Atoi(parts[2]); err == nil && l > 0 {
					limit = l
				}
			}
			targets, err := db.GetReconTargets("all", limit)
			if err != nil || len(targets) == 0 {
				fmt.Fprintf(s.logs, "[yellow]No attack targets tracked yet.[white]\n")
				break
			}
			fmt.Fprintf(s.logs, "[cyan]Tracked Attack & Infrastructure Targets (%d):[white]\n", len(targets))
			fmt.Fprintf(s.logs, "  %-16s | %-12s | %-5s | %-26s | %s\n", "IP ADDRESS", "TYPE", "RISK", "REVERSE DNS (PTR)", "THREAT TAGS")
			fmt.Fprintf(s.logs, "  %s\n", strings.Repeat("-", 90))
			for _, t := range targets {
				riskColor := "[green]"
				if t.RiskScore >= 70 {
					riskColor = "[red]"
				} else if t.RiskScore >= 40 {
					riskColor = "[yellow]"
				}

				rdns := t.ReverseDNS
				if rdns == "" {
					rdns = "-"
				}
				if len(rdns) > 26 {
					rdns = rdns[:23] + "..."
				}

				fmt.Fprintf(s.logs, "  %-16s | %-12s | %s%-5d[white] | %-26s | %s\n",
					tview.Escape(t.IP), tview.Escape(t.SourceType), riskColor, t.RiskScore, tview.Escape(rdns), tview.Escape(t.Tags))
			}

		default:
			targetIP := subCmd
			fmt.Fprintf(s.logs, "[cyan][*] Enriching target %s with PTR and GeoIP...[white]\n", tview.Escape(targetIP))
			go func(ip string) {
				res, err := recon.ScanTarget(ip)
				if err != nil {
					fmt.Fprintf(s.logs, "[red][!] Lookup failed for %s: %v[white]\n", tview.Escape(ip), err)
					return
				}
				riskColor := "[green]"
				if res.RiskScore >= 70 {
					riskColor = "[red]"
				} else if res.RiskScore >= 40 {
					riskColor = "[yellow]"
				}
				fmt.Fprintf(s.logs, "\n[cyan]══════════════════════════════════════════════════════════════════════[white]\n")
				fmt.Fprintf(s.logs, "[cyan]🎯 OSINT INTELLIGENCE REPORT: %s[white]\n", tview.Escape(res.IP))
				fmt.Fprintf(s.logs, "[cyan]══════════════════════════════════════════════════════════════════════[white]\n")
				fmt.Fprintf(s.logs, "  Target IP:        %s\n", tview.Escape(res.IP))
				if res.ReverseDNS != "" {
					fmt.Fprintf(s.logs, "  Reverse DNS PTR:  [green]%s[white]\n", tview.Escape(res.ReverseDNS))
				}
				fmt.Fprintf(s.logs, "  Location:         %s (%s)\n", tview.Escape(res.CountryName), tview.Escape(res.CountryCode))
				if res.ASN != "" {
					fmt.Fprintf(s.logs, "  ASN / Org:        %s (%s)\n", tview.Escape(res.ASN), tview.Escape(res.ASName))
				}
				fmt.Fprintf(s.logs, "  Threat Risk:      %s%d / 100[white]\n", riskColor, res.RiskScore)
				if len(res.Tags) > 0 {
					var escapedTags []string
					for _, tag := range res.Tags {
						escapedTags = append(escapedTags, tview.Escape(tag))
					}
					fmt.Fprintf(s.logs, "  Threat Tags:      [yellow]%s[white]\n", strings.Join(escapedTags, ", "))
				}
				fmt.Fprintf(s.logs, "[cyan]══════════════════════════════════════════════════════════════════════[white]\n\n")
			}(targetIP)
		}

	case "/canary":
		if len(parts) < 2 {
			fmt.Fprintf(s.logs, "[yellow]Syntax: /canary <ip> [token_context][white]\n")
			break
		}
		canaryIP := parts[1]
		ctx := "Manual Canary Token Hit"
		if len(parts) >= 3 {
			ctx = strings.Join(parts[2:], " ")
		}
		target, err := recon.AddManualCanaryHit(canaryIP, ctx)
		if err != nil {
			fmt.Fprintf(s.logs, "[red][!] Failed to add canary hit: %v[white]\n", err)
			break
		}
		fmt.Fprintf(s.logs, "[green][+] Successfully logged canary token hit for IP %s (%s)[white]\n", tview.Escape(target.IP), tview.Escape(ctx))
		fmt.Fprintf(s.logs, "[cyan][*] Queued for PTR and GeoIP enrichment.[white]\n")

	case "/exit":
		s.manager.StopAll()
		return true

	default:
		fmt.Fprintf(s.logs, "[yellow][!] Unknown command: %s. Type /help for help.[white]\n", tview.Escape(command))
	}
	return false
}
