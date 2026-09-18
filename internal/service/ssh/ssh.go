package ssh

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

	"golang.org/x/crypto/ssh"
)

type SSHService struct {
	port      int
	listener  net.Listener
	config    *ssh.ServerConfig
	logger    io.Writer
	isoEngine *isolation.Engine
	ttl       int
}

func (s *SSHService) log(format string, a ...interface{}) {
	if s.logger != nil {
		fmt.Fprintf(s.logger, format+"\n", a...)
	}
}

func (s *SSHService) SetLogger(w io.Writer) {
	s.logger = w
}

func (s *SSHService) EnableIsolation(engine *isolation.Engine) {
	s.isoEngine = engine
}

func NewSSHService(port int) *SSHService {
	svc := &SSHService{port: port, ttl: 300}
	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Capture credentials
			db.RecordCredential(&db.Credential{
				Protocol: "ssh",
				RemoteIP: db.ExtractIP(c.RemoteAddr().String()),
				Username: c.User(),
				Password: string(pass),
			})
			svc.log("[orange][!] SSH Credential Captured: %s:%s from %s[white]", c.User(), string(pass), db.ExtractIP(c.RemoteAddr().String()))
			misp.PushCredential("ssh", c.RemoteAddr().String(), c.User(), string(pass))
			
			// SEAMLESS: If isolation is on, we ACCEPT the password even if it's wrong,
			// but only if the IP is not exceeding the login rate limit.
			if svc.isoEngine != nil {
				if db.AllowLogin(c.RemoteAddr().String()) {
					return nil, nil 
				}
				svc.log("[yellow][!] SSH Login rate limit exceeded for %s. Denying session.[white]", db.ExtractIP(c.RemoteAddr().String()))
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			resp, err := client(c.User(), "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			pass := resp[0]
			db.RecordCredential(&db.Credential{
				Protocol: "ssh",
				RemoteIP: db.ExtractIP(c.RemoteAddr().String()),
				Username: c.User(),
				Password: pass,
			})
			svc.log("[orange][!] SSH Credential Captured (interactive): %s:%s from %s[white]", c.User(), pass, db.ExtractIP(c.RemoteAddr().String()))
			misp.PushCredential("ssh", c.RemoteAddr().String(), c.User(), pass)
			
			if svc.isoEngine != nil {
				if db.AllowLogin(c.RemoteAddr().String()) {
					return nil, nil
				}
				svc.log("[yellow][!] SSH Login rate limit exceeded for %s. Denying session.[white]", db.ExtractIP(c.RemoteAddr().String()))
			}
			return nil, fmt.Errorf("authentication failed")
		},
	}
	svc.config = config

	key, err := ssh.ParsePrivateKey([]byte(dummyHostKey))
	if err == nil {
		svc.config.AddHostKey(key)
	}

	return svc
}

func (s *SSHService) Start(ctx context.Context) error {
	var err error
	s.listener, err = net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", s.port))
	if err != nil {
		return err
	}

	s.log("[green]SSH Service listening on port %d[white]", s.port)

	go func() {
		for {
			l := s.listener
			if l == nil {
				return
			}
			nConn, err := l.Accept()
			if err != nil {
				return
			}

			db.RecordAttempt(&db.Attempt{
				Protocol: "ssh",
				RemoteIP: db.ExtractIP(nConn.RemoteAddr().String()),
				Port:     s.port,
			})

			go s.handleConn(nConn)
		}
	}()

	return nil
}

func (s *SSHService) handleConn(nConn net.Conn) {
	// Perform SSH Handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(nConn, s.config)
	if err != nil {
		nConn.Close()
		return
	}
	defer sshConn.Close()

	// Service global requests
	go ssh.DiscardRequests(reqs)

	if s.isoEngine == nil {
		return
	}

	// SEAMLESS ISOLATION
	s.log("[blue]Spinning up isolation container for SSH user %s... (%ds TTL)[white]", sshConn.User(), s.ttl)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.ttl)*time.Second)
	defer cancel()

	id, ip, err := s.isoEngine.CreateContainer(ctx, "ssh", sshConn.User())
	if err != nil {
		s.log("[red]Failed to create isolation environment: %v[white]", err)
		return
	}
	_ = ip // Not needed for ssh breakout

	// TTL Monitor
	go func() {
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded {
			s.log("[red][!] Session TTL expired for %s[white]", sshConn.User())
			s.isoEngine.StopContainer(context.Background(), id)
		}
	}()

	defer s.isoEngine.StopContainer(context.Background(), id)

	// Handle channels
	for newChan := range chans {
		if newChan.ChannelType() != "session" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			continue
		}

		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell", "exec":
					go func() {
						onCommand := func(cmd string) {
							s.log("[red][!] SSH command executed from %s: %s[white]", db.ExtractIP(sshConn.RemoteAddr().String()), cmd)
							db.RecordCommand(&db.Command{
								Protocol: "ssh",
								RemoteIP: db.ExtractIP(sshConn.RemoteAddr().String()),
								Username: sshConn.User(),
								Command:  cmd,
							})
							misp.PushCommand("ssh", sshConn.RemoteAddr().String(), sshConn.User(), cmd)
						}
						err := s.isoEngine.ExecuteShell(ctx, id, sshConn.User(), channel, channel, channel, onCommand)
						if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, syscall.EPIPE) && !strings.Contains(err.Error(), "use of closed network connection") {
							s.log("[red]Shell Error: %v[white]", err)
						} else {
							s.log("[blue]SSH Session for %s closed gracefully.[white]", sshConn.User())
						}
						channel.Close()
					}()
					req.Reply(true, nil)
				case "pty-req":
					req.Reply(true, nil)
				default:
					req.Reply(false, nil)
				}
			}
		}(requests)
	}
}

func (s *SSHService) Stop() error {
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}

func (s *SSHService) Status() string {
	if s.listener != nil {
		return "Running"
	}
	return "Stopped"
}

func (s *SSHService) Port() int {
	return s.port
}

func (s *SSHService) Protocol() string {
	return "ssh"
}

func (s *SSHService) IsIsolated() bool {
	return s.isoEngine != nil
}

func (s *SSHService) SetTTL(seconds int) {
	s.ttl = seconds
}

func (s *SSHService) GetTTL() int {
	return s.ttl
}

const dummyHostKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAstZMbdn1uJnb6tAQH1eQv08Y6eYjznbYfv7w+2eK+Wi4/Jzx
USCTkbg1CJ6a1Uo3gUJTrlS2T2LDvVcy3c9gmMgE+7TKz25u7JwDUj5klqe6cPRE
4d9S7gng1wAIlqLGaHG2D5tAWoUFG9Dnu1XSSzm04nHGXpRn5MH1EliksW6kxZOZ
VWofJIIzjr3kPrK0e93MSgFljpkwkGkvhr2HOB/EOuLJFq3IyNVUE/4KiVFdhtjY
tdHiJHj0tctQStCGUcQgjBLXu+ui53QO6zkOl1vAcCHCdG5jM87G63LjsTHpsuL3
wre7MD66h+kRUep28vdTNj8ts2aZR0MPBe4u9QIDAQABAoIBAACt8cJlFprp8rz0
p2sHESS47zZMSoyJRQ9Odqnt3chOzo0fJ4eQYR8nnQP4Xkw7KPTTxK+f4MVycZ3x
i97t38cU03gFWtPo7oD1osmYNRehcYLmWrClAZKn9PO8K0wvOCPDctaiV19ArCFL
7OV4UQE6KebGWeOYGsDyv7SfI5kM+e3yOD3hU1wVMVOiRTTy/TffaHKJr2L5x173
XsAtanXCHBXOfLAJ68FXPUQd0Y7GSlpZy0D+GUPlQhOmvuZKqj6rRZUh2xQsSX36
tgshWi3JfSYC5E3er6weYJy/7fCFBvnSqUt2a52I5OCOhWs+HVxE1liargf1xZMi
CkNhqSECgYEA8cSnVkIfSGaUkk50mMkQaxogjXKuk3WqxZT0RrctovM1ljnxX5qs
wzgpE1NcSt/aiRsmwTfdV5EpUgJhr+GpgNCm42beQNDKm44WqDFBeenJJBZ89/3z
m3OumsjcxxrwFDq+4y78KKZaSNeVtzOoiPhdRSum7Xi/ViiWb4MUpjkCgYEAvV1M
th8L4JpnjeUy1w6fB7mDV5JNwf8O9godz5K7cfg/rIwtkAMW0usnAKTJJuQ5Aw38
hbgx9oh97dibcA0R6F+u+N/fCgmYolH1idhnU8OBMvfufZlx/3gbTvXSD8myarMd
ymz1EQrpKUHodBBX7ZWku1al/cWmtl3JAL+WLp0CgYEAvYnxsnNGOSmKoqT1Te6b
e4vRJ3NYH+zow9vCIkprccuAIFUuwUfu12GI+kipG14h4skxedtFIOiB33RUh2G/
1Gg/3hmAdon5vTgI1TVAYsaA1VT4BifGuwFXSqvcQhABVaq0ikEEmQ3JzD+PdT//
idpErPzK8nNudap+PdAi+SkCgYEAp9gPy4lfNLiHOv1Bf98k1Gr5YOB77YzOzQQQ
glDztkQs5Brns7MZQuBNlMN6y+8UHYIDJt8p4fP/cpdAxyO+kLJm249LGZGB6bYt
pf3bMCKk3PFnQYqFwcPKqMU4aOgFLZAPwsGqwm1iV0Bk8qMd3Kd7+NUHkhTj/NbJ
99DZI/0CgYBCNdIeuy2u64bnUWCw8lIKUHSdJgzb0XRCrD6wbv9jcH+0NkgU0yDh
KQEULvvABjsx0zFcMmvt9/3I5vXmFKs5Zf7OFLf1cMO1tIBhv4WxyjRSgUOFDtvz
ZbuRBLvscoOpKNraDOyW2YFbqjAfn3RFRHpV8Thxx7lJ7Y5ykf1H+A==
-----END RSA PRIVATE KEY-----`
