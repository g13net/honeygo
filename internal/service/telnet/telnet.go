package telnet

import (
	"context"
	"errors"
	"fmt"
	"honeygo/internal/db"
	"honeygo/internal/isolation"
	"honeygo/internal/misp"
	"honeygo/internal/sandbox"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
)

type TelnetService struct {
	port      int
	listener  net.Listener
	logger    io.Writer
	isoEngine *isolation.Engine
	ttl       int
}

func (s *TelnetService) log(format string, a ...interface{}) {
	if s.logger != nil {
		fmt.Fprintf(s.logger, format+"\n", a...)
	}
}

func (s *TelnetService) SetLogger(w io.Writer) {
	s.logger = w
}

func (s *TelnetService) EnableIsolation(engine *isolation.Engine) {
	s.isoEngine = engine
}

func NewTelnetService(port int) *TelnetService {
	return &TelnetService{port: port, ttl: 300}
}

func (s *TelnetService) Start(ctx context.Context) error {
	var err error
	s.listener, err = net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", s.port))
	if err != nil {
		return err
	}

	s.log("[green]Telnet Service listening on port %d[white]", s.port)

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

func (s *TelnetService) handleConn(conn net.Conn) {
	defer conn.Close()
	
	// Capture Attempt
	db.RecordAttempt(&db.Attempt{
		Protocol: "telnet",
		RemoteIP: db.ExtractIP(conn.RemoteAddr().String()),
		Port:     s.port,
	})

	// Set initial timeout for login
	conn.SetDeadline(time.Now().Add(2 * time.Minute))
	
	// 1. Capture Username
	fmt.Fprint(conn, "Login: ")
	username, err := readLineSafe(conn)
	if err != nil {
		return
	}
	
	// 2. Capture Password (with Echo suppression)
	conn.Write([]byte{255, 251, 1}) // IAC WILL ECHO
	fmt.Fprint(conn, "Password: ")
	password, err := readLineSafe(conn)
	if err != nil {
		return
	}
	conn.Write([]byte{255, 252, 1}) // IAC WONT ECHO (Restore local echo)
	fmt.Fprint(conn, "\r\n")
	
	// Save to DB
	db.RecordCredential(&db.Credential{
		Protocol: "telnet",
		RemoteIP: db.ExtractIP(conn.RemoteAddr().String()),
		Username: username,
		Password: password,
	})
	
	s.log("[orange][!] Telnet Credential Captured: %s:%s from %s[white]", username, password, db.ExtractIP(conn.RemoteAddr().String()))
	misp.PushCredential("telnet", db.ExtractIP(conn.RemoteAddr().String()), username, password)
	
	// Reset deadline for the actual session
	conn.SetDeadline(time.Time{})

	if s.isoEngine != nil {
		if !db.AllowLogin(conn.RemoteAddr().String()) {
			s.log("[yellow][!] Telnet Login rate limit exceeded for %s. Falling back to mock shell.[white]", db.ExtractIP(conn.RemoteAddr().String()))
		} else {
			s.log("[blue]Handoff: Starting seamless session for %s (%ds TTL)[white]", username, s.ttl)
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.ttl)*time.Second)
			defer cancel()

			id, ip, err := s.isoEngine.CreateContainer(ctx, "telnet", username)
			if err != nil {
				s.log("[red]Failed to create isolation: %v[white]", err)
				return
			}
			_ = ip // Not needed for telnet breakout

			// TTL Monitor
			go func() {
				<-ctx.Done()
				if ctx.Err() == context.DeadlineExceeded {
					s.log("[red][!] Session TTL expired for %s[white]", username)
					s.isoEngine.StopContainer(context.Background(), id)
				}
			}()

			defer s.isoEngine.StopContainer(context.Background(), id)

			fmt.Fprint(conn, "Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-generic x86_64)\r\n\r\n")
			
			// Disable client-side echo and suppress go-ahead for full-duplex terminal behavior
			conn.Write([]byte{255, 251, 1}) // IAC WILL ECHO
			conn.Write([]byte{255, 251, 3}) // IAC WILL SUPPRESS GO AHEAD

			// Wrap connection in TelnetFilter for clean shell handoff
			filter := &TelnetFilter{conn: conn}
			onCommand := func(cmd string) {
				s.log("[red][!] Telnet command executed from %s: %s[white]", db.ExtractIP(conn.RemoteAddr().String()), cmd)
				db.RecordCommand(&db.Command{
					Protocol: "telnet",
					RemoteIP: db.ExtractIP(conn.RemoteAddr().String()),
					Username: username,
					Command:  cmd,
				})
				misp.PushCommand("telnet", conn.RemoteAddr().String(), username, cmd)
			}
			err = s.isoEngine.ExecuteShell(ctx, id, username, filter, filter, filter, onCommand)
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EPIPE) && !strings.Contains(err.Error(), "use of closed network connection") {
				s.log("[red]Shell Error: %v[white]", err)
			} else {
				s.log("[blue]Session for %s closed gracefully.[white]", username)
			}
			return
		}
	}

	// Fallback mock
	sh := sandbox.NewShell(username, "srv-linux-01")
	fmt.Fprint(conn, "Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-generic x86_64)\r\n\r\n")
	for {
		fmt.Fprint(conn, sh.Prompt())
		input, err := readLineSafe(conn)
		if err != nil || input == "exit" {
			return
		}
		s.log("[red][!] Telnet mock command executed from %s: %s[white]", db.ExtractIP(conn.RemoteAddr().String()), input)
		db.RecordCommand(&db.Command{
			Protocol: "telnet",
			RemoteIP: db.ExtractIP(conn.RemoteAddr().String()),
			Username: username,
			Command:  input,
		})
		misp.PushCommand("telnet", conn.RemoteAddr().String(), username, input)
		fmt.Fprint(conn, sh.Execute(input)+"\r\n")
	}
}

// TelnetFilter handles Telnet negotiation and strips IAC/ANSI noise for shell handoff
type TelnetFilter struct {
	conn  net.Conn
	state int
}

const (
	stateNormal = iota
	stateIAC
	stateIAC3
	stateIACSB
	stateESC
	stateCSI
)

func (t *TelnetFilter) Read(p []byte) (n int, err error) {
	for {
		temp := make([]byte, len(p))
		bn, err := t.conn.Read(temp)
		if err != nil {
			return 0, err
		}

		outIdx := 0
		for i := 0; i < bn; i++ {
			b := temp[i]

			switch t.state {
			case stateNormal:
				if b == 255 {
					t.state = stateIAC
				} else if b == 27 {
					t.state = stateESC
				} else if b == 1 {
					// Strip SOH (^A)
					continue
				} else if b == 0 {
					// Strip NULL bytes (Telnet CR NUL artifact often seen as '?')
					continue
				} else if b == '\r' {
					// Normalize line endings for the container shell (\r\n or \r\0 -> \n)
					if i+1 < bn && (temp[i+1] == '\n' || temp[i+1] == 0) {
						i++
					}
					p[outIdx] = '\n'
					outIdx++
				} else {
					p[outIdx] = b
					outIdx++
				}

			case stateIAC:
				if b == 250 { // SB (Subnegotiation)
					t.state = stateIACSB
				} else if b >= 251 && b <= 254 { // WILL/WONT/DO/DONT (3-byte)
					t.state = stateIAC3
				} else {
					// 2-byte sequence or unexpected byte
					t.state = stateNormal
				}

			case stateIAC3:
				// Third byte of WILL/WONT/DO/DONT
				t.state = stateNormal

			case stateIACSB:
				if b == 240 { // SE (Subnegotiation End)
					t.state = stateNormal
				}

			case stateESC:
				if b == '[' {
					t.state = stateCSI
				} else {
					t.state = stateNormal
				}

			case stateCSI:
				// CSI sequences: ESC [ ... <final_char>
				// Final chars are typically in range 0x40-0x7E (A-Z, a-z, etc.)
				if b >= 0x40 && b <= 0x7E {
					t.state = stateNormal
				}
			}
		}

		if outIdx > 0 {
			return outIdx, nil
		}
		// If outIdx == 0, we've filtered everything in this read, loop to get more data
	}
}

func (t *TelnetFilter) Write(p []byte) (n int, err error) {
	// For output, we ensure \n -> \r\n for Telnet clients, avoiding \r\r\n
	// Also filter out Device Status Report (DSR) ESC [ 6 n which triggers CPR responses
	var out []byte
	for i := 0; i < len(p); i++ {
		b := p[i]

		// Filter out ESC [ 6 n (DSR)
		if b == 27 && i+3 < len(p) && p[i+1] == '[' && p[i+2] == '6' && p[i+3] == 'n' {
			i += 3
			continue
		}

		if b == '\n' {
			if i == 0 || p[i-1] != '\r' {
				out = append(out, '\r')
			}
		}
		out = append(out, b)
	}
	_, err = t.conn.Write(out)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// readLineSafe reads bytes until a newline or carriage return, handling all
// Telnet line-ending variants used over real internet connections:
//   - \r\n  — Windows/standard
//   - \r\0  — RFC 854 CR NUL (very common in real Telnet clients over WAN)
//   - \r    — bare CR (some clients)
//   - \n    — bare LF (uncommon but seen from some SSH-tunnelled telnet tools)
func readLineSafe(conn net.Conn) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
		_, err := conn.Read(buf)
		if err != nil {
			return "", err
		}

		char := buf[0]

		// \n alone — done
		if char == '\n' {
			break
		}

		// \r — this IS the line terminator in real Telnet (RFC 854).
		// Peek at the next byte: consume it if it's \n or \0 (CR NUL / CR LF),
		// then break either way.
		if char == '\r' {
			peek := make([]byte, 1)
			conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if _, peekErr := conn.Read(peek); peekErr == nil {
				// Only consume if it's the expected trailing byte; otherwise the
				// byte belongs to the next input and we must not discard it.
				_ = peek
			}
			conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
			break
		}

		// Handle Backspace (ASCII 8 or 127)
		if char == 8 || char == 127 {
			if len(line) > 0 {
				line = line[:len(line)-1]
				conn.Write([]byte{8, 32, 8})
			}
			continue
		}

		// Filter out Telnet IAC sequences (0xFF = 255)
		if char == 255 {
			extra := make([]byte, 2)
			conn.Read(extra)
			continue
		}

		// Filter out ANSI/VT escape sequences (ESC [)
		if char == 27 {
			next := make([]byte, 1)
			conn.Read(next)
			if next[0] == '[' {
				for {
					term := make([]byte, 1)
					conn.Read(term)
					if (term[0] >= 'a' && term[0] <= 'z') || (term[0] >= 'A' && term[0] <= 'Z') {
						break
					}
				}
			}
			continue
		}

		// NUL bytes — strip (artifact of CR NUL sent before username/password)
		if char == 0 {
			continue
		}

		// Printable ASCII only
		if char >= 32 && char <= 126 {
			line = append(line, char)
		}
	}
	return strings.TrimSpace(string(line)), nil
}

func (s *TelnetService) Stop() error {
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}

func (s *TelnetService) Status() string {
	if s.listener != nil {
		return "Running"
	}
	return "Stopped"
}

func (s *TelnetService) Port() int {
	return s.port
}

func (s *TelnetService) Protocol() string {
	return "telnet"
}

func (s *TelnetService) IsIsolated() bool {
	return s.isoEngine != nil
}

func (s *TelnetService) SetTTL(seconds int) {
	s.ttl = seconds
}

func (s *TelnetService) GetTTL() int {
	return s.ttl
}
