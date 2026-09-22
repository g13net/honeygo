# Honeygo v0.5.8

A high-performance, modular Go honeypot and Central Storage Server (CSS) framework engineered to detect, isolate, and profile network intruders. Honeygo combines transparent multi-protocol interception (SSH, Telnet, Web, VNC, Modbus TCP, and Siemens S7comm), rootless container sandbox isolation, industrial SCADA deception, deep threat correlation analytics, bit-perfect raw payload forensics, and native OpenCTI threat feed server integration (TAXII 2.1, STIX 2.1, RSS 2.0, and CSV).

---

## Table of Contents

- [Features](#features)
- [System Architecture](#system-architecture)
- [Installation Guide](#installation-guide)
  - [1. Prerequisites & Package Installation](#1-prerequisites--package-installation)
  - [2. Podman Rootless Socket Setup](#2-podman-rootless-socket-setup)
  - [3. Clone & Build Container Images](#3-clone--build-container-images)
  - [4. Compile Binary & Configure Permissions](#4-compile-binary--configure-permissions)
- [Command-Line Flags Reference](#command-line-flags-reference)
- [Interactive TUI Slash Commands](#interactive-tui-slash-commands)
- [Basic & Advanced Use Cases](#basic--advanced-use-cases)
  - [Use Case 1: Standalone Honeypot with Container Isolation & WebUI](#use-case-1-standalone-honeypot-with-container-isolation--webui)
  - [Use Case 2: Industrial Control Systems (ICS / SCADA) Deception Grid](#use-case-2-industrial-control-systems-ics--scada-deception-grid)
  - [Use Case 3: Distributed Multi-Sensor Grid with Central Storage Server (CSS)](#use-case-3-distributed-multi-sensor-grid-with-central-storage-server-css)
  - [Use Case 4: Web Honeypot with Deception Profiles & AI/LLM Scraper Traps](#use-case-4-web-honeypot-with-deception-profiles--aillm-scraper-traps)
  - [Use Case 5: OpenCTI Threat Feed Server (TAXII 2.1 & STIX 2.1)](#use-case-5-opencti-threat-feed-server-taxii-21--stix-21)
  - [Use Case 6: MISP Threat Sharing & Telegram Alerting](#use-case-6-misp-threat-sharing--telegram-alerting)
  - [Use Case 7: Attacker Payload Forensics & Shellcode Extraction](#use-case-7-attacker-payload-forensics--shellcode-extraction)
  - [Use Case 8: Verbosity Control: Quiet Production Mode vs. Live Telemetry](#use-case-8-verbosity-control-quiet-production-mode-vs-live-telemetry)
- [Deception Profiles Reference](#deception-profiles-reference)
- [SSL/TLS Certificates Setup](#ssltls-certificates-setup)
- [Project Documentation](#project-documentation)

---

## Features

### 1. Multi-Protocol Honeypot Interception
- **SSH (Port 22/2222, RFC 4252/4253)**: Full SSH protocol negotiation, credential harvesting, interactive PTY terminal emulation, keystroke timing tracking, and automatic container sandboxing.
- **Telnet (Port 23/2323, RFC 854)**: Standard IAC Telnet option negotiation, login harvesting, banner spoofing, and rate-limited container isolation fallback.
- **Web / HTTP (Port 80/8080/443, RFC 7230/7231)**: Low-interaction deception server emulating Apache, Microsoft IIS, Cisco Switch, AWS Cloud Canaries, or custom multi-path profiles with dedicated AI/LLM bot traps (`/llms.txt`, `/.env`).
- **VNC (Port 5900, RFB 003.008)**: Virtual Network Computing handshake emulation, authentication challenge generation, and password brute-force interception.
- **Modbus TCP (Port 502, Modbus Protocol V1.1b)**: Industrial SCADA PLC honeypot emulating Schneider Electric, Mitsubishi Common-Q, and Triconex controllers with function code parsing (FC 0x01–0x06, 0x10, 0x2B).
- **Siemens S7comm (Port 102, ISO-on-TCP RFC 1006 / ISO 8073 COTP)**: Siemens S7-300, S7-1200, and S7-1500 PLC emulation capturing COTP connection requests and S7comm PDUs.

### 2. Deep Threat Intelligence & Full-Dataset Correlation Engine
- **Accurate Full-Dataset Aggregation**: Zero-allocation HTTP streaming parser and database cursor scanning aggregate 100,000+ web scans and 75,000+ credentials without truncation or artificial query sampling limits.
- **Accurate Hit Counts & Unique IPs**: Delivers verified, exact hit totals (e.g. 6,000+ hits to `GET /`) and distinct remote IP counts across all web URIs and credentials.
- **Throttled Background Worker**: Continuous asynchronous correlation pre-computation with a 2-second debounce window and 5-second cooldown period, preventing CPU thrashing during heavy port scans or DDoS events.
- **Cross-Protocol Attacker Scoring**: Multi-vector threat scoring (0–100) and risk level assignment (LOW, MEDIUM, HIGH, CRITICAL) evaluating multi-protocol activity, port diversity, multi-sensor detection, and recency.
- **Global Heatmap Density**: Geolocation mapping showing attacker density with CARTO Basemaps integration.

### 3. Industrial Control Systems (ICS / SCADA) Forensics
- **Dedicated ICS Dashboard**: High-level and granular telemetry tracking Modbus and S7comm attacks, unique attacker IPs, and function code distributions.
- **Function Code Analytics**: Automatic decoding of PLC operations including Read Coils (FC 0x01), Read Holding Registers (FC 0x03), Write Single Coil (FC 0x05), Write Single Register (FC 0x06), Write Multiple Registers (FC 0x10), and Read Device Identification (FC 0x2B).
- **Raw Hex Payloads**: Complete capture and hex dump display of attacker PLC command frames for deep protocol inspection.

### 4. Hardened Container Sandbox Isolation
- **Rootless Podman & Docker**: Runs entirely without root privileges via `cgroupfs` user namespaces.
- **Resource Constraints**: Strict limits enforced per session: **0.10 CPU cores**, **64MB RAM**, and **20 maximum PIDs** to defeat cryptocurrency miners, fork-bombs, and memory exhaustion attacks.
- **PTY Keystroke Reconstruction**: Reconstructs raw character streams into clean, readable command strings, stripping backspaces, cursor motions, and ANSI control codes.
- **Anti-Churn Rate Limiting**: Enforces a strict quota of **1 successful login per 30 seconds per IP** for container allocation. Excess connections automatically fall back to an in-memory mock shell with zero container overhead.
- **Automatic Purge**: Short-lived container instances are purged after session termination or TTL expiry.

### 5. Central Storage Server (CSS) & Multi-Sensor Grid
- **Clustered Sensor Aggregation**: Central CSS server aggregates event telemetry from dozens of distributed sensors in real-time.
- **Micro-Batched Forwarding**: Sensors forward attempts, credentials, and commands over persistent HTTP connection pools without local SQLite disk writes.
- **Token-Based Authentication**: Enforce bearer token authentication (`--css-token` / `--css-auth`) on sensor checkins and feed queries.
- **Sensor Orchestration**: Operators can view connected sensors, adjust checkin heartbeat TTLs (`--sensor-ttl`), rename sensor display labels, and manage services from the WebUI.
- **Strict Isolation Rules**: Services requiring container isolation (e.g., Modbus, S7comm) cannot be started on remote sensors unless the target sensor has active container runtime support.

### 6. OpenCTI & Threat Feed Server
- **JSON / STIX 2.1 Feed (`/feed/json`)**: Standard JSON array or STIX 2.1 bundle formatted for SIEM ingestion and OpenCTI connectors.
- **TAXII 2.1 Server (`/taxii2/`)**: Full TAXII 2.1 discovery endpoint and collection objects (`/taxii2/collections/honeygo-events/objects/`).
- **RSS 2.0 Feed (`/feed/rss`)**: Standard XML feed with attacker IP summaries, protocols, and timestamps for RSS readers and alert bots.
- **CSV Feed (`/feed/csv`)**: Tabular event exports for spreadsheet analysis and SIEM data imports.

### 7. MISP Threat Sharing & Telegram Notifications
- **Automated MISP Dispatches**: Automatically pushes captured attacker IPs, credentials, executed commands, HTTP scan paths, and PLC attacks to a remote MISP server.
- **Live Diagnostics & Audit Logging**: Real-time sync counters (total pushed vs. failed), connection latency check, canary test event dispatcher, and detailed audit log table in the WebUI.
- **Telegram Intrusion Alerts**: Immediate notifications sent to Telegram chat groups upon new honeypot attempts and credential captures.

### 8. Bit-Perfect Raw HTTP Request Forensics
- **Lossless Request Capture**: Complete raw request strings preserved up to 4KB per scan.
- **Multi-Format Downloads**: View and download payloads as:
  - Raw binary (`.bin`)
  - Formatted hex dump with offset and ASCII sidebar (`.hex`)
  - Continuous raw hex string (`.hex`)
  - Printable ASCII with `\xNN` escape sequences (`.txt`)
  - Base64 encoding (`.b64`)
  - JSON metadata bundle (`.json`)

### 9. Logging & Verbosity Control
- **Quiet Mode by Default**: Background connection attempts, routine scans, and heartbeats are suppressed from the live console stream to keep the terminal clean.
- **First-Time Sensor Notification**: When a new sensor node registers for the first time, an informational notice is always displayed unconditionally.
- **Runtime & CLI Toggles**: Enable live streaming anytime with `--info` on the command line or `/info on` in the interactive TUI.
- **Persistent Structured Logging**: All events, service transitions, container events, and errors are permanently recorded in `honeygo.log` and accessible via `/syslog`.

---

## System Architecture

```
                                    +-----------------------------------------+
                                    |       OpenCTI / Threat Feed Clients      |
                                    |  TAXII 2.1 | STIX 2.1 | RSS 2.0 | CSV   |
                                    +--------------------+--------------------+
                                                         ^
                                                         | HTTP / HTTPS (/feed/*, /taxii2/*)
                                                         |
+--------------------------+        +--------------------+--------------------+
|  Remote Sensor Nodes     |        |      Central Storage Server (CSS)       |
|  - sensor-edge-01        | =====> |  - WebUI Analytics Dashboard (Port 8090)|
|  - sensor-edge-02        |  HTTP  |  - High-Velocity Ingestion Queue        |
|  (Micro-batched stream)  |  POST  |  - SQLite WAL Engine + Threat Analytics |
+--------------------------+        +--------------------+--------------------+
                                                         |
                                 +-----------------------+-----------------------+
                                 |                                               |
                                 v                                               v
                    +------------------------+                      +------------------------+
                    |      MISP Server       |                      |  Telegram Alert Bot    |
                    | (Automated IOC Push)   |                      | (Real-Time Intrusions) |
                    +------------------------+                      +------------------------+

[ Local Sensor Ingestion Pipeline ]
Attacker Connection
       |
       +---> Port Interception (SSH, Telnet, Web, VNC, Modbus TCP, Siemens S7comm)
                |
                +---> Low-Interaction Handshake / Protocol Parser
                |        |
                |        +---> Capture Credentials, Payloads, PLC Function Codes
                |
                +---> Container Sandbox Isolation (Podman / Docker)
                         |
                         +---> 0.10 CPU, 64MB RAM, 20 PIDs Limit
                         +---> PTY Keystroke Reconstruction
                         +---> Rate Limiter (1 login / 30s per IP)
                         +---> Fallback to In-Memory Simulated Mock Shell
```

---

## Installation Guide

Follow these instructions to install system dependencies, configure rootless Podman, build honeypot guest images, compile the Honeygo binary, and configure non-root execution permissions.

### 1. Prerequisites & Package Installation

Honeygo requires **Go 1.21+** and **Podman** (or Docker).

#### Debian / Ubuntu / Kali
```bash
sudo apt update
sudo apt install -y golang-go podman crun slirp4netns netavark aardvark-dns fuse-overlayfs uidmap make libcap2-bin git
```

#### Fedora / RHEL / Rocky Linux
```bash
sudo dnf install -y golang podman crun slirp4netns netavark aardvark-dns fuse-overlayfs shadow-utils make libcap git
```

#### Arch Linux / Manjaro
```bash
sudo pacman -Syu --needed go podman crun slirp4netns netavark aardvark-dns fuse-overlayfs make libcap git
```

---

### 2. Podman Rootless Socket Setup

Enable the unprivileged user-level Podman service socket so Honeygo can communicate with the container engine without `sudo`:

```bash
# Enable and start user-level Podman socket
systemctl --user enable --now podman.socket

# Verify that the user socket is active
systemctl --user status podman.socket
```

---

### 3. Clone & Build Container Images

Clone the repository and build the guest honeypot container images:

```bash
# Clone repository
git clone https://github.com/g13net/honeygo.git
cd honeygo

# Download Go dependencies
go mod download

# Build all guest container images (SSH, Telnet, Web, VNC, Modbus, S7comm)
make images
```

> **Note on Rootless Podman:** The `Makefile` automatically detects Podman and passes `--cgroup-manager=cgroupfs --format=docker` to eliminate D-Bus permission errors during rootless builds. If using Docker, `make images` will invoke `docker build` transparently.

---

### 4. Compile Binary & Configure Permissions

Compile the Honeygo binary and grant low-port binding capabilities so the process can listen on privileged ports (e.g. 22, 23, 80, 102, 443, 502) as a standard unprivileged user:

```bash
# Compile Honeygo
go build -o honeygo ./cmd/honeygo

# Grant low-port binding capability to the binary
sudo setcap cap_net_bind_service=+ep ./honeygo

# Run Honeygo as an unprivileged user without sudo!
./honeygo --isolation --ssh --telnet --modbus --s7comm --analytics
```

> **Important:** Running `go build` creates a new binary, which clears file capabilities. Re-run `sudo setcap cap_net_bind_service=+ep ./honeygo` whenever you recompile the binary.

---

## Command-Line Flags Reference

Strict Unix syntax is enforced: single dashes are reserved for single-character flags (`-h`, `-v`, `-k`), while all full-word options require double dashes (`--`).

| Category | Flag | Default | Description |
|---|---|---|---|
| **Core & Engine** | `--isolation` | `false` | Enable rootless container sandbox isolation (Podman/Docker) |
| | `--db <path>` | `honeygo.db` | Path to SQLite database |
| | `--clear-db` | `false` | Purge all data from the database on startup |
| **Honeypot Services** | `--ssh` | `false` | Enable SSH honeypot |
| | `--ssh-port <port>` | `2222` | SSH honeypot listening port |
| | `--telnet` | `false` | Enable Telnet honeypot |
| | `--telnet-port <port>` | `2323` | Telnet honeypot listening port |
| | `--web` | `false` | Enable Web / HTTP honeypot |
| | `--web-port <port>` | `8080` | Web honeypot listening port |
| | `--web-profile <prof>` | `apache` | Deception profile: `apache`, `iis`, `cisco`, `aws-canary`, `pizzashop`, `nginx`, `tomcat`, `login-portal`, `router-admin`, or custom template path |
| | `--web-ssl` | `false` | Enable SSL/TLS encryption on Web honeypot (requires `./certs/`) |
| | `--vnc` | `false` | Enable VNC honeypot |
| | `--vnc-port <port>` | `5900` | VNC honeypot listening port |
| **Industrial (ICS/SCADA)** | `--modbus` | `false` | Enable Modbus TCP PLC honeypot (requires container isolation) |
| | `--modbus-port <port>` | `502` | Modbus TCP listening port |
| | `--modbus-profile <prof>`| `schneider` | PLC profile: `schneider`, `common-q`, `triconex` |
| | `--s7comm` | `false` | Enable Siemens S7comm PLC honeypot (requires container isolation) |
| | `--s7comm-port <port>` | `102` | Siemens S7comm listening port |
| **Central Storage Server** | `--css-server` | `false` | Launch in Central Storage Server (CSS) mode |
| | `--css-port <port>` | `8090` | CSS server & WebUI dashboard port |
| | `--css-url <url>` | `""` | Connect as remote sensor to CSS server (e.g. `https://css.corp:8090`) |
| | `--css-token <token>` | `""` | Shared authentication Bearer token for CSS server or sensor |
| | `--css-auth` | `false` | Enforce token authentication on CSS endpoints |
| | `-k`, `--insecure` | `false` | Ignore self-signed SSL/TLS certificates when connecting to CSS |
| | `--sensor-id <id>` | auto | Custom unique identifier for this sensor node |
| | `--sensor-ttl <seconds>` | `15` | Sensor heartbeat TTL checkin interval in seconds |
| **WebUI & Dashboard** | `--analytics` | `false` | Start standalone WebUI Analytics Dashboard server |
| | `--analytics-port <port>`| `8090` | WebUI Analytics Dashboard port |
| | `--ssl` | `false` | Enable SSL/TLS encryption for CSS server and WebUI (requires `./certs/server.crt` and `./certs/server.key`) |
| | `--carto-key <key>` | `""` | CARTO Basemaps API key for threat heatmap tiles |
| **External Alerting** | `--misp-url <url>` | `""` | Remote MISP server URL (e.g. `https://misp.corp.internal`) |
| | `--misp-key <key>` | `""` | MISP API authentication key |
| | `--misp-skip-verify` | `false` | Skip SSL/TLS certificate verification for MISP |
| | `--telegram-token <token>`| `""` | Telegram Bot API authentication token |
| | `--telegram-chat-id <id>`| `""` | Telegram Chat ID for intrusion alert delivery |
| **Output & Logging** | `--info`, `--verbose` | `false` | Enable live streaming of informational messages (connected sensors, events, errors; default: disabled) |
| **Information** | `-h`, `--help` | `false` | Display categorized help screen and exit |
| | `-v`, `--version` | `false` | Print version information (`v0.5.8`) and exit |

---

## Interactive TUI Slash Commands

When Honeygo launches, it enters an interactive CRT console shell. Operators can enter slash commands to manage services, inspect logs, configure integrations, and adjust settings in real-time.

```
+----------------------------------------------------------------------------------------------------+
|  Command                       | Description & Examples                                            |
+----------------------------------------------------------------------------------------------------+
|  /services [svc]               | List all available services or inspect a specific service type.  |
|                                | Example: /services ssh, /services modbus                          |
|  /status                       | Show all running services, listening ports, and isolation states.  |
|  /start <svc> <port> [opts]    | Start a honeypot service on a port.                               |
|                                | Options: --profile <prof>, --isolated, --ttl <seconds>            |
|                                | Example: /start ssh 22 --isolated                                |
|                                | Example: /start web 80 --profile aws-canary                       |
|                                | Example: /start modbus 502 --isolated --profile triconex          |
|  /stop <svc> [port]            | Stop all instances of a service, or a specific port.             |
|                                | Example: /stop ssh 22, /stop web                                  |
|  /logs [subcommand]            | View connection logs, inspect raw HTTP requests, or export logs:  |
|                                |   /logs web [limit]         - View recent web scans               |
|                                |   /logs req <id> [format]   - Inspect full raw request            |
|                                |   /logs download <id> <fp>  - Download request payload to file    |
|                                |   /logs export <fp> [svc]   - Bulk export logs (json, hex, txt)   |
|  /creds                        | Display all captured usernames, passwords, and password hashes.   |
|  /webprofile <profile>         | Change active web profile: apache, iis, cisco, aws-canary,       |
|                                | pizzashop, or template path in profiles/.                         |
|  /modbusprofile <profile>      | Change active Modbus PLC profile: schneider, common-q, triconex.   |
|  /analytics [cmd] [port]       | Control WebUI dashboard: /analytics start 8090 [--ssl],           |
|                                | /analytics stop, /analytics status.                               |
|  /css [subcommand]             | Manage CSS server and sensor clustering:                          |
|                                |   /css server start [port]  - Start CSS aggregator               |
|                                |   /css connect <url> [-k]   - Connect as remote sensor            |
|                                |   /css disconnect           - Disconnect from CSS                 |
|                                |   /css sensors              - List connected cluster sensors      |
|                                |   /css token <token>        - Set shared authentication token     |
|                                |   /css carto <key>          - Configure CARTO heatmap API key     |
|  /recon [subcommand]           | Threat hunting & OSINT reconnaissance:                            |
|                                |   /recon <ip>               - Query infrastructure OSINT for IP   |
|                                |   /recon list               - Show tracked attacker recon targets |
|                                |   /recon auto [on|off]      - Toggle automatic background OSINT   |
|                                |   /recon scanall            - Trigger OSINT scan on all targets   |
|  /canary <ip> [token_info]     | Manually record an external Canary Token trigger IP.              |
|  /telegram <token> <chat_id>   | Configure Telegram intrusion alert bot credentials.               |
|  /misp [url] [key] [--skip]    | Configure MISP threat intelligence sharing. Use /misp off to off. |
|  /syslog [category] [limit]    | View structured system logs: SYSTEM, SERVICE, ISOLATION, CSS,    |
|                                | DATABASE, ALERT, WEBUI, MISP. Example: /syslog ISOLATION 50       |
|  /info [on|off|status]         | Toggle live streaming of informational messages (events/errors).  |
|                                | First-time sensor connections are always displayed unconditionally|
|  /cleardb                      | Purge all data from SQLite database.                               |
|  /clear                        | Clear active CRT log window.                                      |
|  /help [command] [sub]         | Context-sensitive help system (e.g. /help start ssh, /help css).  |
|  /exit                         | Gracefully stop all honeypot services and exit Honeygo.            |
+----------------------------------------------------------------------------------------------------+
```

---

## Basic & Advanced Use Cases

### Use Case 1: Standalone Honeypot with Container Isolation & WebUI

Run an all-in-one standalone honeypot on standard ports (SSH on 22, Telnet on 23, Web on 80, VNC on 5900) with container sandboxes and the WebUI dashboard enabled on port 8090:

```bash
# Run with rootless container isolation and WebUI dashboard (HTTP)
./honeygo --isolation \
  --ssh --ssh-port 22 \
  --telnet --telnet-port 23 \
  --web --web-port 80 --web-profile apache \
  --vnc --vnc-port 5900 \
  --analytics --analytics-port 8090
```

1. Attackers connecting to SSH on port 22 or Telnet on port 23 are dropped into isolated rootless containers with 0.10 CPU and 64MB memory caps.
2. Web requests on port 80 receive an Apache 2.4 default response while logging all scan paths and user-agents.
3. Access the dashboard by opening `http://localhost:8090` in any modern web browser.

---

### Use Case 2: Industrial Control Systems (ICS / SCADA) Deception Grid

Deploy an industrial honeypot to capture targeted reconnaissance and unauthorized command execution against critical infrastructure controllers (Modbus TCP on 502 and Siemens S7comm on 102):

```bash
# Deploy Modbus TCP and Siemens S7comm honeypots with Triconex safety PLC emulation
./honeygo --isolation \
  --modbus --modbus-port 502 --modbus-profile triconex \
  --s7comm --s7comm-port 102 \
  --analytics --analytics-port 8090
```

1. **Modbus TCP**: Emulates a Triconex Safety Instrumented System (SIS) controller. Every coil read (FC 0x01), register write (FC 0x06, 0x10), and diagnostic query is parsed and logged.
2. **Siemens S7comm**: Negotiates ISO-on-TCP connection setups and logs S7comm memory read/write requests.
3. **WebUI ICS Forensics**: Navigate to `http://localhost:8090` and click **ICS / SCADA** to inspect attack distributions, targeted function codes, and raw hex command frames.

---

### Use Case 3: Distributed Multi-Sensor Grid with Central Storage Server (CSS)

Deploy a centralized storage server and connect remote sensor nodes located across different networks (e.g., DMZ, corporate internal, and cloud environments).

#### Step A: Launch Central Storage Server (CSS)
```bash
# Start CSS on port 8090 with token authentication and CARTO heatmap integration
./honeygo --css-server --css-port 8090 \
  --css-token "HoneygoClusterSecret2026" --css-auth \
  --carto-key "YOUR_CARTO_API_KEY"
```

To run CSS over SSL/TLS HTTPS:
```bash
# Place your certs in ./certs/server.crt and ./certs/server.key
./honeygo --css-server --css-port 8090 --ssl \
  --css-token "HoneygoClusterSecret2026" --css-auth
```

#### Step B: Launch Remote Sensors
```bash
# Sensor Node 1 (DMZ edge node, forwards SSH and Telnet over HTTPS, ignoring self-signed certs)
./honeygo --isolation --ssh --ssh-port 22 --telnet --telnet-port 23 \
  --css-url https://css.corp.internal:8090 -k \
  --css-token "HoneygoClusterSecret2026" \
  --sensor-id "sensor-edge-dmz" \
  --sensor-ttl 15

# Sensor Node 2 (Industrial plant network, forwards Modbus and S7comm telemetry)
./honeygo --isolation --modbus --modbus-port 502 --s7comm --s7comm-port 102 \
  --css-url https://css.corp.internal:8090 -k \
  --css-token "HoneygoClusterSecret2026" \
  --sensor-id "sensor-plant-plc" \
  --sensor-ttl 30
```

- **Zero Local Disk Writes**: Remote sensors stream events directly over HTTP/HTTPS; no local SQLite database is created on edge sensors.
- **Global Dropdown Filter**: In the WebUI, use the sensor selector in the top bar to filter analytics for a specific sensor node or view aggregated metrics across `all`.
- **First-Time Sensor Notice**: When `sensor-edge-dmz` connects for the first time, CSS prints a connection notice in the CRT shell.

---

### Use Case 4: Web Honeypot with Deception Profiles & AI/LLM Scraper Traps

Deploy an authentic deceptive web presence with LLM-specific reconnaissance traps:

```bash
# Launch PizzaShop profile with AI discovery endpoints on port 8080
./honeygo --web --web-port 8080 --web-profile pizzashop --analytics

# Or run Cisco Switch deception profile on port 80
./honeygo --web --web-port 80 --web-profile cisco --analytics

# Or run AWS Cloud Canary deception profile over HTTPS on port 443
./honeygo --web --web-port 443 --web-ssl --web-profile aws-canary --analytics
```

- **`pizzashop` Profile**: Delivers a retro 1990s pizza parlor website featuring active traps for automated crawlers and AI bots:
  - `/.env`: Exposes realistic dummy API credentials that trigger Canary alerts if exercised.
  - `/llms.txt` and `/llms-full.txt`: Deceptive context files designed to capture and fingerprint LLM scrapers.
- **`cisco` Profile**: Spoofs a Cisco Catalyst management interface, trapping brute-force credential stuffing attempts.
- **`aws-canary` Profile**: Emulates an internal AWS metadata endpoint / Cloud Canary service.

---

### Use Case 5: OpenCTI Threat Feed Server (TAXII 2.1 & STIX 2.1)

Integrate Honeygo directly into OpenCTI or any TAXII 2.1-compatible Threat Intelligence Platform (TIP):

```bash
# Launch Honeygo CSS with threat feed server enabled
./honeygo --css-server --css-port 8090 --css-token "MyFeedTokenSecret"
```

#### Ingesting via cURL or OpenCTI:

1. **TAXII 2.1 Server Discovery**:
   ```bash
   curl -H "Authorization: Bearer MyFeedTokenSecret" http://localhost:8090/taxii2/
   ```
2. **TAXII 2.1 Collections & STIX 2.1 Objects**:
   ```bash
   curl -H "Authorization: Bearer MyFeedTokenSecret" \
     http://localhost:8090/taxii2/collections/honeygo-events/objects/
   ```
3. **Direct STIX 2.1 Bundle**:
   ```bash
   curl -H "Authorization: Bearer MyFeedTokenSecret" \
     "http://localhost:8090/feed/json?format=stix2"
   ```
4. **CSV Feed Export**:
   ```bash
   curl -H "Authorization: Bearer MyFeedTokenSecret" http://localhost:8090/feed/csv
   ```
5. **RSS 2.0 XML Feed**:
   ```bash
   curl -H "Authorization: Bearer MyFeedTokenSecret" http://localhost:8090/feed/rss
   ```

---

### Use Case 6: MISP Threat Sharing & Telegram Alerting

Automate bidirectional threat sharing with your organization's MISP instance and receive real-time mobile push notifications:

```bash
# Start Honeygo with MISP threat sharing and Telegram bot alerts
./honeygo --isolation --ssh --telnet --web \
  --misp-url "https://misp.security.corp" \
  --misp-key "A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6" \
  --telegram-token "123456789:ABCdefGHIjklMNOpqrSTUvwxYZ" \
  --telegram-chat-id "-1001234567890" \
  --analytics
```

- **MISP**: Connection attempts, harvested passwords, web paths, and commands are enriched and pushed into MISP events as indicators.
- **Telegram**: Sends structured markdown messages with attacker IP, protocol, country, and credentials immediately upon capture.
- **WebUI MISP Settings**: Operators can test connections, dispatch test canary events, and inspect the real-time transmission audit log under the **MISP Configuration** section in the WebUI.

---

### Use Case 7: Attacker Payload Forensics & Shellcode Extraction

Inspect, analyze, and extract exploit payloads, shellcode, and automated scan requests captured by Honeygo:

#### Inspecting via CLI:
```text
# 1. View recent web scan requests with IDs
/logs web 25

# 2. Inspect a specific request payload in formatted hex dump mode
/logs req 142 hex

# 3. Download raw binary bytes of payload for Ghidra / Wireshark analysis
/logs download 142 /tmp/exploit_payload.bin raw

# 4. Export all captured web payloads as a JSON forensic archive
/logs export /tmp/web_forensics.json web json
```

#### Inspecting via WebUI:
1. Open the WebUI at `http://localhost:8090` and navigate to **Activity Logs** -> **Web Scans**.
2. Click **Inspect** on any row to open the modal view showing the complete request line, HTTP headers, client fingerprint, and payload.
3. Click any format button (**`.bin`**, **`.hex`**, **`.txt`**, **`.b64`**, or **`.json`**) to download the payload with bit-perfect fidelity.

---

### Use Case 8: Verbosity Control: Quiet Production Mode vs. Live Telemetry

Control console clutter without losing audit traceability:

#### Quiet Mode (Default):
```bash
# Starts in clean quiet mode: background attempts and errors are suppressed from live TUI
./honeygo --isolation --ssh --telnet --analytics
```
- First-time sensor registrations are **always displayed** unconditionally.
- All events are permanently recorded in `honeygo.db` and `honeygo.log`.
- To inspect background activity, use `/syslog` or view the WebUI.

#### Verbose Telemetry Mode:
```bash
# Enable live streaming from startup
./honeygo --info --isolation --ssh --telnet --analytics
```

#### Runtime Control via Interactive TUI:
```text
/info           # Toggle streaming on or off
/info on        # Enable live streaming
/info off       # Disable live streaming (quiet mode)
/info status    # Check current streaming status
```

---

## Deception Profiles Reference

### Web Honeypot Profiles (`--web-profile <profile>`)

| Profile Name | Description | Key Features |
|---|---|---|
| `apache` *(default)* | Apache 2.4 HTTP Server on Ubuntu Linux | Emulates default Debian/Ubuntu Apache landing page with genuine headers |
| `iis` | Microsoft Internet Information Services 10.0 | Emulates standard Windows Server IIS welcome page |
| `cisco` | Cisco Small Business / Catalyst Switch | Emulates network device authentication page; traps router exploit scans |
| `aws-canary` | AWS Cloud Infrastructure & EC2 Metadata | Emulates internal AWS metadata services and Canary token honey-tokens |
| `pizzashop` | 1990s Pizza Restaurant with AI/LLM Discovery | Retro marketing site with active `/.env`, `/llms.txt`, `/llms-full.txt`, and `/v1/models` scraper traps |
| `nginx` | Nginx 1.18 HTTP Server on Ubuntu Linux | Emulates standard Ubuntu Nginx welcome page |
| `tomcat` | Apache Tomcat 9.0 Application Server | Emulates Tomcat landing page and `/manager/html` 401 Basic auth trap |
| `login-portal` | Corporate Single Sign-On Employee Portal | Emulates enterprise SSO login interface and harvests form submissions |
| `router-admin` | RouterOS / Edge Gateway Administration | Emulates network router management interface with 401 Basic auth trap |
| `<custom.txt>` | Custom Multi-Path Template File | Path to custom text file in `profiles/` or filesystem (e.g. `profiles/generic_form.txt`, `profiles/jenkins_login.txt`) |

> [!TIP]
> For the complete specification on creating custom multi-endpoint web profiles, route directives (`=== PATH:`), method splitters (`=== POST ===`), and dynamic placeholders (`[BODY_LEN]`, `[CURRENT_DATE]`), see [PROFILES.md](PROFILES.md).

### Modbus PLC Profiles (`--modbus-profile <profile>`)

| Profile Name | Target Controller | Emulated Features |
|---|---|---|
| `schneider` *(default)* | Schneider Electric Modicon M340/M580 | Emulates industrial PLC coil and holding registers; answers FC 0x2B device queries |
| `common-q` | Mitsubishi MELSEC System Q | Emulates Japanese factory automation PLC registers and discrete inputs |
| `triconex` | Schneider Electric Triconex Safety SIS | Emulates safety instrumented system controllers used in refineries and energy grids |

---

## SSL/TLS Certificates Setup

Honeygo uses a zero-configuration convention for SSL/TLS certificates:

1. **Certificate Directory**: Store your server certificate and private key in the `./certs/` directory in the application root:
   - `./certs/server.crt`
   - `./certs/server.key`
   *(Any PEM-encoded `.crt`, `.key`, or `.pem` file placed in `./certs/` is automatically discovered).*
2. **WebUI & CSS Server SSL**: Enable HTTPS encryption for the WebUI and CSS aggregator by passing `--ssl`:
   ```bash
   ./honeygo --css-server --css-port 8090 --ssl
   ```
3. **Web Honeypot SSL**: Enable HTTPS encryption for the web honeypot by passing `--web-ssl`:
   ```bash
   ./honeygo --web --web-port 443 --web-ssl --web-profile apache
   ```
4. **Self-Signed Certificates (`-k` / `--insecure`)**: When connecting remote sensors to a CSS server that uses a self-signed certificate, pass `-k` (or `--insecure`) to bypass TLS hostname verification:
   ```bash
   ./honeygo --css-url https://css.corp:8090 -k --css-token "MyToken"
   ```
---

## License

Honeygo is released under the MIT License. See `LICENSE` for details.

