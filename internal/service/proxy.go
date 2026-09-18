package service

import (
	"io"
	"net"
	"sync"
	"time"
)

// ProxyConnection pipes traffic between two connections.
func ProxyConnection(client net.Conn, targetAddr string, preFunc func(net.Conn) error) error {
	var target net.Conn
	var err error

	for i := 0; i < 15; i++ {
		target, err = net.DialTimeout("tcp", targetAddr, 2*time.Second)
		if err == nil {
			break
		}
		time.Sleep(1 * time.Second)
	}

	if err != nil {
		return err
	}
	defer target.Close()

	if preFunc != nil {
		if err := preFunc(target); err != nil {
			return err
		}
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// Copy from client to target (FILTER DSR RESPONSE)
	go func() {
		defer wg.Done()
		statefulFilterAndCopy(target, client, true)
		if tcpConn, ok := target.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	// Copy from target to client (FILTER DSR QUERY)
	go func() {
		defer wg.Done()
		statefulFilterAndCopy(client, target, false)
		if tcpConn, ok := client.(*net.TCPConn); ok {
			_ = tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
	return nil
}

func statefulFilterAndCopy(dst io.Writer, src io.Reader, isClientInput bool) {
	buf := make([]byte, 4096)
	state := 0 // 0: normal, 1: ESC, 2: CSI ([)
	var seq []byte
	
	for {
		n, err := src.Read(buf)
		if n > 0 {
			clean := make([]byte, 0, n)
			for i := 0; i < n; i++ {
				b := buf[i]
				switch state {
				case 0:
					if b == 27 {
						state = 1
						seq = []byte{27}
					} else {
						clean = append(clean, b)
					}
				case 1:
					if b == '[' {
						state = 2
						seq = append(seq, '[')
					} else {
						clean = append(clean, 27, b)
						state = 0
					}
				case 2:
					seq = append(seq, b)
					// DSR Response: ESC [ <num> ; <num> R
					// DSR Query: ESC [ 6 n
					if b == 'R' && isClientInput {
						state = 0 // Swallow DSR response from client
					} else if b == 'n' && !isClientInput {
						state = 0 // Swallow DSR query from container
					} else if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') {
						// Other sequence, pass it through
						clean = append(clean, seq...)
						state = 0
					}
					// If numeric or semicolon, stay in state 2
				}
			}
			if len(clean) > 0 {
				_, _ = dst.Write(clean)
			}
		}
		if err != nil {
			break
		}
	}
}
