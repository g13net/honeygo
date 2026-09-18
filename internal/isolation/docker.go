package isolation

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	docker "github.com/fsouza/go-dockerclient"
	"honeygo/internal/syslog"
)

const (
	// defaultPoolSize is the number of containers kept warm and ready to assign.
	defaultPoolSize = 3
	// poolImage is the image used for pre-warmed containers.
	poolImage = "honeygo-base"
)

type poolInfo struct {
	channel chan string
	cancel  context.CancelFunc
}

type Engine struct {
	cli       *docker.Client
	logger    io.Writer
	pools     map[string]*poolInfo
	poolMutex sync.RWMutex
	done      chan struct{}
}

// IsAvailable returns true if the Docker/Podman container isolation engine is accessible.
func IsAvailable() bool {
	engine, err := NewEngine(nil)
	if err != nil {
		return false
	}
	engine.Close()
	return true
}

func NewEngine(logger io.Writer) (*Engine, error) {
	// 1. Honour explicit DOCKER_HOST env var (works for both root and rootless)
	if dockerHost := os.Getenv("DOCKER_HOST"); dockerHost != "" {
		if cli, err := docker.NewClient(dockerHost); err == nil {
			if cli.Ping() == nil {
				return newEngine(cli, logger), nil
			}
		}
	}

	// 2. Try the standard environment-based client (picks up DOCKER_HOST automatically)
	if cli, err := docker.NewClientFromEnv(); err == nil {
		if cli.Ping() == nil {
			return newEngine(cli, logger), nil
		}
	}

	uid := os.Getuid()

	// 3. Build a priority-ordered list of sockets to probe
	var candidatePaths []string

	if uid == 0 {
		// Running as root (direct or via sudo):
		//   a) Rootful Podman system socket (requires: sudo systemctl start podman.socket)
		candidatePaths = append(candidatePaths, "unix:///run/podman/podman.sock")
		//   b) Rootful Docker socket
		candidatePaths = append(candidatePaths, "unix:///var/run/docker.sock")
		//   c) SUDO_UID: recover the calling user's rootless socket
		if sudoUID := os.Getenv("SUDO_UID"); sudoUID != "" {
			candidatePaths = append(candidatePaths,
				fmt.Sprintf("unix:///run/user/%s/podman/podman.sock", sudoUID),
				fmt.Sprintf("unix:///run/user/%s/docker.sock", sudoUID),
			)
		}
	} else {
		// Rootless user: check their XDG_RUNTIME_DIR socket locations
		candidatePaths = append(candidatePaths,
			fmt.Sprintf("unix:///run/user/%d/podman/podman.sock", uid),
			fmt.Sprintf("unix:///run/user/%d/docker.sock", uid),
			"unix:///var/run/docker.sock",
		)
	}

	for _, path := range candidatePaths {
		cleanPath := path
		if len(path) > 7 && path[:7] == "unix://" {
			cleanPath = path[7:]
		}
		if _, statErr := os.Stat(cleanPath); statErr != nil {
			continue
		}
		if cli, err := docker.NewClient(path); err == nil {
			if cli.Ping() == nil {
				return newEngine(cli, logger), nil
			}
		}
	}

	hint := fmt.Sprintf("/run/user/%d/podman/podman.sock", uid)
	if uid == 0 {
		hint = "/run/podman/podman.sock"
	}
	return nil, fmt.Errorf(
		"could not connect to docker/podman daemon (uid=%d).\n\n"+
			"If running via sudo for privileged ports, choose one of:\n\n"+
			"  Option A — Rootful Podman (simplest with sudo):\n"+
			"    sudo systemctl start podman.socket\n"+
			"    sudo ./honeygo --isolation=true --ssh --telnet --mysql\n\n"+
			"  Option B — Pass your rootless socket through sudo:\n"+
			"    systemctl --user start podman.socket   # as your normal user\n"+
			"    sudo DOCKER_HOST=unix:///run/user/$(id -u)/podman/podman.sock \\\n"+
			"         ./honeygo --isolation=true --ssh --telnet --mysql\n\n"+
			"  Option C — Use net_bind_service capability instead of sudo:\n"+
			"    sudo setcap cap_net_bind_service=+ep ./honeygo\n"+
			"    systemctl --user start podman.socket\n"+
			"    ./honeygo --isolation=true --telnet --mysql\n\n"+
			"Expected socket: %s",
		uid, hint,
	)
}

// newEngine constructs an Engine
func newEngine(cli *docker.Client, logger io.Writer) *Engine {
	return &Engine{
		cli:    cli,
		logger: logger,
		pools:  make(map[string]*poolInfo),
		done:   make(chan struct{}),
	}
}

// StartPoolWarmer initiates keeping a pre-warmed pool for the specific protocol.
func (e *Engine) StartPoolWarmer(protocol string) {
	e.poolMutex.Lock()
	defer e.poolMutex.Unlock()

	if _, exists := e.pools[protocol]; exists {
		return // Already warming
	}

	ctx, cancel := context.WithCancel(context.Background())
	pool := make(chan string, defaultPoolSize)
	e.pools[protocol] = &poolInfo{
		channel: pool,
		cancel:  cancel,
	}
	go e.poolWarmer(ctx, protocol, pool)
}

// StopPoolWarmer stops the pool warmer for a specific protocol and destroys all pre-warmed containers.
func (e *Engine) StopPoolWarmer(protocol string) {
	e.poolMutex.Lock()
	info, exists := e.pools[protocol]
	if !exists {
		e.poolMutex.Unlock()
		return
	}
	delete(e.pools, protocol)
	e.poolMutex.Unlock()

	e.log("Stopping pool warmer and cleaning up containers for %s...", protocol)
	info.cancel()

	// Drain and stop
	for {
		select {
		case id := <-info.channel:
			e.cli.StopContainer(id, 2)
		default:
			return
		}
	}
}

// poolWarmer continuously keeps the specific warm pool full in the background.
func (e *Engine) poolWarmer(ctx context.Context, protocol string, pool chan string) {
	for {
		select {
		case <-e.done:
			// Drain and stop all pre-warmed containers on shutdown
			for {
				select {
				case id := <-pool:
					e.cli.StopContainer(id, 2)
				default:
					return
				}
			}
		case <-ctx.Done():
			// Individual pool stopped
			return
		default:
		}

		if len(pool) < defaultPoolSize {
			rawImage := "honeygo-" + protocol
			imageName := e.resolveImage(rawImage)
			if imageName == "" {
				fallback := e.resolveImage(poolImage)
				if fallback != "" {
					imageName = fallback
				} else {
					imageName = poolImage
				}
				e.log("Image %s not found for warm pool, falling back to %s", rawImage, imageName)
			}

			id, err := e.createRawContainer(imageName)
			if err != nil {
				// Image likely not built yet — back off and retry
				time.Sleep(10 * time.Second)
				continue
			}
			select {
			case pool <- id:
				e.log("Pre-warmed %s container ready (%d/%d in pool)", protocol, len(pool), defaultPoolSize)
			default:
				// Pool just filled by concurrent path — discard extra
				e.cli.StopContainer(id, 1)
			}
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// resolveImage attempts to resolve an image name checking Podman localhost/ prefixes.
func (e *Engine) resolveImage(name string) string {
	candidates := []string{
		name,
		name + ":latest",
		"localhost/" + name,
		"localhost/" + name + ":latest",
	}
	for _, c := range candidates {
		if _, err := e.cli.InspectImage(c); err == nil {
			return c
		}
	}
	return ""
}

// Close stops the pool warmer and cleans up all pre-warmed containers.
func (e *Engine) Close() {
	close(e.done)
}

// createRawContainer starts a new idle container from the given image.
func (e *Engine) createRawContainer(image string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := e.cli.CreateContainer(docker.CreateContainerOptions{
		Config: &docker.Config{
			Image:    image,
			Hostname: "srv-linux-01",
			Env: []string{
				"TERM=xterm",
				`PS1=\u@\h:\w\$ `,
			},
		},
		HostConfig: &docker.HostConfig{
			AutoRemove:  true,
			NetworkMode: "none",
			Memory:      64 * 1024 * 1024,  // 64MB RAM limit
			NanoCPUs:    100000000,        // 0.10 CPU cores limit (10% of one core)
			PidsLimit:   int64Ptr(20),     // Max 20 processes limit (prevents fork-bombs)
		},
		Context: ctx,
	})
	if err != nil {
		return "", err
	}
	if err := e.cli.StartContainer(resp.ID, nil); err != nil {
		return "", err
	}
	return resp.ID, nil
}

func (e *Engine) SetLogger(w io.Writer) {
	e.logger = w
}

func (e *Engine) log(format string, a ...interface{}) {
	if e.logger != nil {
		fmt.Fprintf(e.logger, "[blue][Isolation][white] "+format+"\n", a...)
	}
}

func (e *Engine) CreateContainer(ctx context.Context, protocol string, user string) (string, string, error) {
	e.log("Assigning isolated environment for %s (user: %s)...", protocol, user)

	e.poolMutex.RLock()
	info, exists := e.pools[protocol]
	e.poolMutex.RUnlock()

	if exists {
		// Try to assign a pre-warmed container instantly
		for {
			select {
			case id := <-info.channel:
				// Verify the container is still running
				c, err := e.cli.InspectContainer(id)
				if err != nil || (c != nil && !c.State.Running) {
					e.log("Discarding stale container %s from pool", id[:12])
					continue
				}
				e.log("Assigned pre-warmed container %s (instant)", id[:12])
				syslog.Info(syslog.CategoryIsolation, "Allocated pre-warmed container %s for %s session", id[:12], protocol)
				return id, "", nil
			default:
				e.log("%s pool empty — creating container on-demand (may be slow)...", protocol)
				syslog.Warn(syslog.CategoryIsolation, "%s container pool empty, building container on-demand", protocol)
				goto on_demand
			}
		}
	} else {
		e.log("No warm pool for %s — creating container on-demand (may be slow)...", protocol)
		syslog.Warn(syslog.CategoryIsolation, "No pool warmer for %s, creating container on-demand", protocol)
	}

on_demand:

	// Pool was empty: create fresh, prefer protocol-specific image
	rawImage := "honeygo-" + protocol
	imageName := e.resolveImage(rawImage)
	if imageName == "" {
		fallback := e.resolveImage(poolImage)
		if fallback != "" {
			imageName = fallback
		} else {
			imageName = poolImage
		}
		e.log("Image %s not found, falling back to %s", rawImage, imageName)
		syslog.Warn(syslog.CategoryIsolation, "Image %s not found, using base image %s", rawImage, imageName)
	}

	id, err := e.createRawContainer(imageName)
	if err != nil {
		syslog.Error(syslog.CategoryIsolation, "Failed to create on-demand container for %s: %v", protocol, err)
		return "", "", err
	}

	e.log("Started on-demand container %s", id[:12])
	syslog.Info(syslog.CategoryIsolation, "Started on-demand container %s for %s session", id[:12], protocol)
	return id, "", nil
}

func (e *Engine) StopContainer(ctx context.Context, id string) error {
	e.log("Cleaning up environment %s...", id[:12])
	return e.cli.StopContainer(id, 5)
}

const (
	stateNormal = iota
	stateEscape
	stateCSI
)

type KeystrokeReconstructor struct {
	buffer []byte
	state  int
}

func (kr *KeystrokeReconstructor) Process(b byte) (string, bool) {
	switch kr.state {
	case stateNormal:
		if b == 27 { // ESC
			kr.state = stateEscape
			return "", false
		}
		if b == '\r' || b == '\n' {
			if len(kr.buffer) > 0 {
				cmd := string(kr.buffer)
				kr.buffer = nil
				return cmd, true
			}
			return "", false
		}
		if b == 0x7f || b == 0x08 { // Backspace
			if len(kr.buffer) > 0 {
				kr.buffer = kr.buffer[:len(kr.buffer)-1]
			}
			return "", false
		}
		if len(kr.buffer) >= 4096 { // Memory exhaustion limit
			return "", false
		}
		if b >= 32 && b <= 126 { // Printable ASCII
			kr.buffer = append(kr.buffer, b)
		}

	case stateEscape:
		if b == '[' {
			kr.state = stateCSI
		} else {
			kr.state = stateNormal
		}

	case stateCSI:
		if b >= 0x40 && b <= 0x7E { // Final character of CSI sequence
			kr.state = stateNormal
		}
	}
	return "", false
}

type InterceptingReader struct {
	r             io.Reader
	reconstructor *KeystrokeReconstructor
	onCommand     func(string)
}

func NewInterceptingReader(r io.Reader, onCommand func(string)) *InterceptingReader {
	return &InterceptingReader{
		r:             r,
		reconstructor: &KeystrokeReconstructor{},
		onCommand:     onCommand,
	}
}

func (ir *InterceptingReader) Read(p []byte) (n int, err error) {
	n, err = ir.r.Read(p)
	if n > 0 && ir.onCommand != nil {
		for i := 0; i < n; i++ {
			if cmd, ok := ir.reconstructor.Process(p[i]); ok {
				ir.onCommand(cmd)
			}
		}
	}
	return n, err
}

func (e *Engine) ExecuteShell(ctx context.Context, containerID string, user string, stdin io.Reader, stdout, stderr io.Writer, onCommand func(string)) error {
	// Always exec as root inside the container. Attacker-supplied usernames
	// (e.g. "dwdefw") will never exist in the container's /etc/passwd, and
	// Podman/Docker validates the User field at the API level — rejecting the
	// exec with a 500 error before the shell starts. The container is a fake
	// honeypot environment so running as root is correct and expected.
	exec, err := e.cli.CreateExec(docker.CreateExecOptions{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          true,
		Cmd:          []string{"/bin/sh", "-i"},
		Container:    containerID,
		User:         "root",
		Context:      ctx,
	})
	if err != nil {
		return err
	}

	var inputStream io.Reader = stdin
	if onCommand != nil {
		inputStream = NewInterceptingReader(stdin, onCommand)
	}

	return e.cli.StartExec(exec.ID, docker.StartExecOptions{
		Tty:          true,
		InputStream:  inputStream,
		OutputStream: stdout,
		ErrorStream:  stderr,
		RawTerminal:  true,
		Context:      ctx,
	})
}

func (e *Engine) ExecuteBinaryProxy(ctx context.Context, containerID string, stream io.ReadWriter, command string) error {
	cmdParts := strings.Split(command, " ")
	exec, err := e.cli.CreateExec(docker.CreateExecOptions{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
		Cmd:          cmdParts,
		Container:    containerID,
		User:         "root",
		Context:      ctx,
	})
	if err != nil {
		return err
	}

	return e.cli.StartExec(exec.ID, docker.StartExecOptions{
		Tty:          false,
		InputStream:  stream,
		OutputStream: stream,
		ErrorStream:  e.logger, // Forward internal errors to manager logger
		Context:      ctx,
	})
}

// ExecuteBinaryStream starts an exec and returns a bidirectional stream linked to its stdin/stdout.
// The caller is responsible for bridging this stream to the client.
func (e *Engine) ExecuteBinaryStream(ctx context.Context, containerID string, command string) (io.ReadWriteCloser, error) {
	cmdParts := strings.Split(command, " ")
	exec, err := e.cli.CreateExec(docker.CreateExecOptions{
		AttachStdin:  true,
		AttachStdout: true,
		AttachStderr: true,
		Tty:          false,
		Cmd:          cmdParts,
		Container:    containerID,
		User:         "root",
		Context:      ctx,
	})
	if err != nil {
		return nil, err
	}

	// Use pipes to create a ReadWriteCloser
	inRead, inWrite := io.Pipe()
	outRead, outWrite := io.Pipe()

	errChan := make(chan error, 1)
	go func() {
		errChan <- e.cli.StartExec(exec.ID, docker.StartExecOptions{
			Tty:          false,
			InputStream:  inRead,
			OutputStream: outWrite,
			ErrorStream:  e.logger,
			Context:      ctx,
		})
	}()

	// Watchdog to ensure pipes are closed if context expires
	go func() {
		<-ctx.Done()
		inRead.Close()
		inWrite.Close()
		outRead.Close()
		outWrite.Close()
	}()

	return &execStream{
		in:     inWrite,
		out:    outRead,
		closer: func() { inWrite.Close(); outRead.Close() },
	}, nil
}

type execStream struct {
	in     *io.PipeWriter
	out    *io.PipeReader
	closer func()
}

func (s *execStream) Read(p []byte) (n int, err error)  { return s.out.Read(p) }
func (s *execStream) Write(p []byte) (n int, err error) { return s.in.Write(p) }
func (s *execStream) Close() error {
	s.closer()
	return nil
}

func int64Ptr(v int64) *int64 {
	return &v
}
