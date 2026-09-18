package vnc

import (
	"context"
	"errors"
	"fmt"
	"honeygo/internal/db"
	"honeygo/internal/isolation"
	"honeygo/internal/misp"
	"io"
	"net"
	"strings"
	"syscall"
	"time"
)

// RFB Protocol Constants
const (
	VersionString = "RFB 003.008\n"
)

// Static challenge for credential "cracking" (same as vnclowpot for consistency)
var Challenge = []byte{
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

type VNCService struct {
	port      int
	listener  net.Listener
	logger    io.Writer
	isoEngine *isolation.Engine
	ttl       int
}

func NewVNCService(port int) *VNCService {
	return &VNCService{port: port, ttl: 300}
}

func (s *VNCService) log(format string, a ...interface{}) {
	if s.logger != nil {
		fmt.Fprintf(s.logger, "[orange][VNC][white] "+format+"\n", a...)
	}
}

func (s *VNCService) SetLogger(w io.Writer) {
	s.logger = w
}

func (s *VNCService) EnableIsolation(engine *isolation.Engine) {
	s.isoEngine = engine
}

func (s *VNCService) Start(ctx context.Context) error {
	var err error
	s.listener, err = net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", s.port))
	if err != nil {
		return err
	}

	s.log("[green]VNC Service listening on port %d[white]", s.port)

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

func (s *VNCService) handleConn(conn net.Conn) {
	defer conn.Close()

	// Capture Attempt
	db.RecordAttempt(&db.Attempt{
		Protocol: "vnc",
		RemoteIP: db.ExtractIP(conn.RemoteAddr().String()),
		Port:     s.port,
	})

	// 1. Handshake: Version
	if _, err := conn.Write([]byte(VersionString)); err != nil {
		return
	}

	verBuf := make([]byte, len(VersionString))
	if _, err := io.ReadFull(conn, verBuf); err != nil {
		return
	}

	// 2. Security Types (Offer VNC Auth - Type 2)
	// Byte 1: Number of types (1)
	// Byte 2: Security Type 2 (VNC Auth)
	if _, err := conn.Write([]byte{0x01, 0x02}); err != nil {
		return
	}

	selBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, selBuf); err != nil {
		return
	}

	if selBuf[0] != 0x02 {
		s.log("[yellow]Client requested unsupported security type: %d[white]", selBuf[0])
		return
	}

	// 3. VNC Auth: Challenge
	if _, err := conn.Write(Challenge); err != nil {
		return
	}

	// 4. VNC Auth: Response (16 bytes)
	respBuf := make([]byte, 16)
	if _, err := io.ReadFull(conn, respBuf); err != nil {
		return
	}

	// Check for common passwords (simple dictionary for the 0-challenge)
	password := "unknown"
	responseHex := fmt.Sprintf("%X", respBuf)
	if p, ok := db.CommonVNCResponses[responseHex]; ok {
		password = p
	}

	// Log Credentials
	db.RecordCredential(&db.Credential{
		Protocol: "vnc",
		RemoteIP: db.ExtractIP(conn.RemoteAddr().String()),
		Username: "vnc", // VNC typically doesn't have a username in this auth mode
		Password: responseHex,
	})

	misp.PushCredential("vnc", conn.RemoteAddr().String(), "vnc", responseHex)

	s.log("[orange][!] VNC Credential Captured: %s from %s[white]", password, db.ExtractIP(conn.RemoteAddr().String()))

	if s.isoEngine != nil {
		s.log("[blue]Handoff: Starting isolated VNC session (%ds TTL)[white]", s.ttl)
		
		// 5. Security Result: OK (0,0,0,0)
		if _, err := conn.Write([]byte{0x00, 0x00, 0x00, 0x00}); err != nil {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.ttl)*time.Second)
		defer cancel()

		id, _, err := s.isoEngine.CreateContainer(ctx, "vnc", "vnc")
		if err != nil {
			s.log("[red]Failed to create isolation: %v[white]", err)
			return
		}
		
		defer s.isoEngine.StopContainer(context.Background(), id)

		// 5.5 Set TTL watchdog
		go func() {
			<-ctx.Done()
			if ctx.Err() == context.DeadlineExceeded {
				s.log("[red][!] Session TTL expired for VNC session[white]")
				s.isoEngine.StopContainer(context.Background(), id)
			}
		}()
		

		// Bridge the connection
		// 6. Connect to container's x11vnc and sync handshake
		cConn, err := s.isoEngine.ExecuteBinaryStream(ctx, id, "socat - TCP:localhost:5900")
		if err != nil {
			s.log("[red]Failed to connect to container proxy: %v[white]", err)
			return
		}
		defer cConn.Close()

		// Perform handshake synchronization with container
		// A. Read version banner from container
		buf := make([]byte, len(VersionString))
		if _, err := io.ReadFull(cConn, buf); err != nil {
			s.log("[red]Sync Error (Version Read): %v[white]", err)
			return
		}
		// B. Send version response to container
		if _, err := cConn.Write([]byte(VersionString)); err != nil {
			return
		}
		// C. Read security types from container (Expect 0x01 0x01 for None)
		secBuf := make([]byte, 2)
		if _, err := io.ReadFull(cConn, secBuf); err != nil {
			return
		}
		// D. Send security selection (None - 1)
		if _, err := cConn.Write([]byte{0x01}); err != nil {
			return
		}
		// E. Read security result (Expect 0x00 0x00 0x00 0x00 for OK)
		resBuf := make([]byte, 4)
		if _, err := io.ReadFull(cConn, resBuf); err != nil {
			return
		}

		// Now both sides are synchronized at the "ready for ClientInit" state.
		// F. Bidirectional bridge
		errChan := make(chan error, 2)
		go func() {
			_, err := io.Copy(cConn, conn)
			errChan <- err
		}()
		go func() {
			_, err := io.Copy(conn, cConn)
			errChan <- err
		}()

		err = <-errChan
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EPIPE) && !strings.Contains(err.Error(), "use of closed network connection") {
			s.log("[red]VNC Bridge Error: %v[white]", err)
		} else {
			s.log("[blue]VNC Session closed gracefully.[white]")
		}
		return
	}

	// Default: Fail (0,0,0,1) + Error Message
	msg := "Authentication failed"
	failure := []byte{0x00, 0x00, 0x00, 0x01}
	binaryLen := make([]byte, 4)
	binaryLen[3] = byte(len(msg))
	conn.Write(append(append(failure, binaryLen...), []byte(msg)...))
}

func (s *VNCService) Stop() error {
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}

func (s *VNCService) Status() string {
	if s.listener != nil {
		return "Running"
	}
	return "Stopped"
}

func (s *VNCService) Port() int {
	return s.port
}

func (s *VNCService) Protocol() string {
	return "vnc"
}

func (s *VNCService) IsIsolated() bool {
	return s.isoEngine != nil
}

func (s *VNCService) SetTTL(seconds int) {
	s.ttl = seconds
}

func (s *VNCService) GetTTL() int {
	return s.ttl
}
