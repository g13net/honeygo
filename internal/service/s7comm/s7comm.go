package s7comm

import (
	"context"
	"encoding/binary"
	"fmt"
	"honeygo/internal/db"
	"honeygo/internal/isolation"
	"honeygo/internal/misp"
	"io"
	"net"
	"time"
)

// COTP PDU Types
const (
	CotpCr = 0xE0 // Connection Request
	CotpCc = 0xD0 // Connection Confirm
	CotpDt = 0xF0 // Data Data
)

// S7comm Message Types (ROSCTR)
const (
	S7MsgJob     = 0x01
	S7MsgAckData = 0x03
	S7MsgUserData = 0x07
)

// S7comm Functions
const (
	S7FcReadVar   = 0x04
	S7FcWriteVar  = 0x05
	S7FcSetupComm = 0xF0
)

type S7CommService struct {
	port      int
	listener  net.Listener
	logger    io.Writer
	isoEngine *isolation.Engine
	ttl       int
}

func NewS7CommService(port int) *S7CommService {
	return &S7CommService{
		port: port,
		ttl:  300,
	}
}

func (s *S7CommService) SetLogger(w io.Writer) {
	s.logger = w
}

func (s *S7CommService) log(format string, a ...interface{}) {
	if s.logger != nil {
		fmt.Fprintf(s.logger, format+"\n", a...)
	}
}

func (s *S7CommService) EnableIsolation(engine *isolation.Engine) {
	s.isoEngine = engine
}

func (s *S7CommService) Start(ctx context.Context) error {
	if s.isoEngine == nil {
		return fmt.Errorf("s7comm PLC service requires container isolation (must enable isolation)")
	}
	var err error
	s.listener, err = net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", s.port))
	if err != nil {
		return err
	}

	s.log("[green]S7comm (ISO-on-TCP) Service listening on port %d[white]", s.port)

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

func (s *S7CommService) handleConn(conn net.Conn) {
	defer conn.Close()

	remoteIP := db.ExtractIP(conn.RemoteAddr().String())

	s.log("[orange][!] S7comm ISO-on-TCP connection from %s[white]", remoteIP)

	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		tpktHeader := make([]byte, 4)
		_, err := io.ReadFull(conn, tpktHeader)
		if err != nil {
			break
		}

		if tpktHeader[0] != 0x03 {
			// RFC 1006 TPKT version must be 3
			break
		}

		tpktLen := binary.BigEndian.Uint16(tpktHeader[2:4])
		if tpktLen < 4 {
			break
		}

		payloadLen := int(tpktLen - 4)
		payload := make([]byte, payloadLen)
		_, err = io.ReadFull(conn, payload)
		if err != nil {
			break
		}

		if len(payload) == 0 {
			break
		}

		cotpLen := int(payload[0])
		if len(payload) < cotpLen+1 {
			break
		}

		cotpPduType := payload[1] & 0xF0

		rawHex := fmt.Sprintf("%X", append(tpktHeader, payload...))
		db.RecordAttempt(&db.Attempt{
			Protocol: "s7comm",
			RemoteIP: remoteIP,
			Port:     s.port,
			RawData:  rawHex,
		})

		switch cotpPduType {
		case CotpCr:
			s.handleConnectionRequest(conn, remoteIP, payload[:cotpLen+1])
		case CotpDt:
			s.handleS7Data(conn, remoteIP, payload[cotpLen+1:])
		}
	}
}

func (s *S7CommService) handleConnectionRequest(conn net.Conn, remoteIP string, cotpData []byte) {
	srcRef := uint16(0x0001)
	dstRef := uint16(0x0000)
	if len(cotpData) >= 5 {
		dstRef = binary.BigEndian.Uint16(cotpData[2:4])
		srcRef = binary.BigEndian.Uint16(cotpData[4:6])
	}

	cmdStr := fmt.Sprintf("S7comm COTP Connection-Request SrcRef=0x%04X DstRef=0x%04X", srcRef, dstRef)
	s.log("[red][!] S7comm handshake initiated from %s: %s[white]", remoteIP, cmdStr)

	db.RecordCommand(&db.Command{
		Protocol: "s7comm",
		RemoteIP: remoteIP,
		Username: "s7-client",
		Command:  cmdStr,
	})
	misp.PushCommand("s7comm", remoteIP, "s7-client", cmdStr)

	// Send COTP Connection Confirm (CC)
	cotpResp := []byte{
		0x0B, // Length
		CotpCc,
		byte(srcRef >> 8), byte(srcRef), // dstRef = client's srcRef
		byte(dstRef >> 8), byte(dstRef), // srcRef
		0x00,                            // Class
		0xC1, 0x02, 0x01, 0x00,          // TSAP
		0xC0, 0x01, 0x0A,                // TPDU Size
	}

	s.sendTpkt(conn, cotpResp)
}

func (s *S7CommService) handleS7Data(conn net.Conn, remoteIP string, s7Data []byte) {
	if len(s7Data) < 10 {
		return
	}

	if s7Data[0] != 0x32 {
		// S7 Protocol ID must be 0x32
		return
	}

	msgType := s7Data[1]
	pduRef := binary.BigEndian.Uint16(s7Data[4:6])
	paramLen := binary.BigEndian.Uint16(s7Data[6:8])
	dataLen := binary.BigEndian.Uint16(s7Data[8:10])

	_ = dataLen

	if len(s7Data) < 10+int(paramLen) {
		return
	}

	param := s7Data[10 : 10+paramLen]
	data := s7Data[10+paramLen:]

	if len(param) == 0 {
		return
	}

	fn := param[0]
	cmdStr := fmt.Sprintf("S7comm MsgType=0x%02X Function=0x%02X PduRef=%d", msgType, fn, pduRef)

	switch fn {
	case S7FcSetupComm:
		cmdStr = fmt.Sprintf("S7comm SetupCommunication PduRef=%d", pduRef)
		s.sendSetupCommResponse(conn, pduRef)

	case S7FcReadVar:
		cmdStr = fmt.Sprintf("S7comm ReadVar PduRef=%d", pduRef)
		s.sendReadVarResponse(conn, pduRef, param)

	case S7FcWriteVar:
		cmdStr = fmt.Sprintf("S7comm WriteVar PduRef=%d", pduRef)
		s.sendWriteVarResponse(conn, pduRef, param)

	case 0x00: // User Data / SZL Read
		if msgType == S7MsgUserData || (len(param) > 1 && param[1] == 0x04) {
			cmdStr = fmt.Sprintf("S7comm SZL-Read (System Identification Query) PduRef=%d", pduRef)
			s.sendSzlReadResponse(conn, pduRef, data)
		} else {
			s.sendGenericAckResponse(conn, pduRef, fn)
		}

	default:
		s.sendGenericAckResponse(conn, pduRef, fn)
	}

	s.log("[red][!] S7comm command executed from %s: %s[white]", remoteIP, cmdStr)
	db.RecordCommand(&db.Command{
		Protocol: "s7comm",
		RemoteIP: remoteIP,
		Username: "s7-admin",
		Command:  cmdStr,
	})
	misp.PushCommand("s7comm", remoteIP, "s7-admin", cmdStr)
}

func (s *S7CommService) sendSetupCommResponse(conn net.Conn, pduRef uint16) {
	// S7 Header (12 bytes for Ack-Data with Error Class/Code)
	header := make([]byte, 12)
	header[0] = 0x32
	header[1] = S7MsgAckData
	header[2] = 0x00
	header[3] = 0x00
	binary.BigEndian.PutUint16(header[4:6], pduRef)
	binary.BigEndian.PutUint16(header[6:8], 8) // Param length = 8
	binary.BigEndian.PutUint16(header[8:10], 0) // Data length = 0
	header[10] = 0x00                           // Error class = 0
	header[11] = 0x00                           // Error code = 0

	param := []byte{
		S7FcSetupComm, 0x00,
		0x00, 0x01, // Max AMQ calling = 1
		0x00, 0x01, // Max AMQ called = 1
		0x01, 0xE0, // PDU length = 480 bytes
	}

	cotpData := append([]byte{0x02, CotpDt, 0x80}, append(header, param...)...)
	s.sendTpkt(conn, cotpData)
}

func (s *S7CommService) sendReadVarResponse(conn net.Conn, pduRef uint16, param []byte) {
	itemCount := byte(1)
	if len(param) > 1 {
		itemCount = param[1]
	}

	header := make([]byte, 12)
	header[0] = 0x32
	header[1] = S7MsgAckData
	binary.BigEndian.PutUint16(header[4:6], pduRef)
	binary.BigEndian.PutUint16(header[6:8], 2) // Param len = 2
	binary.BigEndian.PutUint16(header[8:10], 9) // Data len = 9

	resParam := []byte{S7FcReadVar, itemCount}
	// Data: Return Code 0xFF (Success), Transport Size 0x04 (BIT/BYTE), Length (bits), Payload
	resData := []byte{
		0xFF,       // Success
		0x04,       // Transport size
		0x00, 0x20, // Length = 32 bits (4 bytes)
		0x00, 0x64, 0x01, 0xF4, // Sample PLC data bytes (100, 500)
	}

	cotpData := append([]byte{0x02, CotpDt, 0x80}, append(header, append(resParam, resData...)...)...)
	s.sendTpkt(conn, cotpData)
}

func (s *S7CommService) sendWriteVarResponse(conn net.Conn, pduRef uint16, param []byte) {
	itemCount := byte(1)
	if len(param) > 1 {
		itemCount = param[1]
	}

	header := make([]byte, 12)
	header[0] = 0x32
	header[1] = S7MsgAckData
	binary.BigEndian.PutUint16(header[4:6], pduRef)
	binary.BigEndian.PutUint16(header[6:8], 2)
	binary.BigEndian.PutUint16(header[8:10], 1)

	resParam := []byte{S7FcWriteVar, itemCount}
	resData := []byte{0xFF} // Success

	cotpData := append([]byte{0x02, CotpDt, 0x80}, append(header, append(resParam, resData...)...)...)
	s.sendTpkt(conn, cotpData)
}

func (s *S7CommService) sendSzlReadResponse(conn net.Conn, pduRef uint16, reqData []byte) {
	// Simulate Siemens S7-1200 CPU 1214C SZL System Identification Response
	plcModule := "CPU 1214C DC/DC/DC"
	plcOrderCode := "6ES7 214-1AG40-0XB0"
	plcFirmware := "V4.2.3"

	szlPayload := fmt.Sprintf("Siemens AG %s %s Firmware %s", plcModule, plcOrderCode, plcFirmware)
	dataLen := uint16(len(szlPayload) + 4)

	header := make([]byte, 12)
	header[0] = 0x32
	header[1] = S7MsgUserData
	binary.BigEndian.PutUint16(header[4:6], pduRef)
	binary.BigEndian.PutUint16(header[6:8], 8)
	binary.BigEndian.PutUint16(header[8:10], dataLen)

	param := []byte{0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00}
	dataHeader := []byte{0xFF, 0x09, byte(len(szlPayload) >> 8), byte(len(szlPayload))}
	data := append(dataHeader, []byte(szlPayload)...)

	cotpData := append([]byte{0x02, CotpDt, 0x80}, append(header, append(param, data...)...)...)
	s.sendTpkt(conn, cotpData)
}

func (s *S7CommService) sendGenericAckResponse(conn net.Conn, pduRef uint16, fn byte) {
	header := make([]byte, 12)
	header[0] = 0x32
	header[1] = S7MsgAckData
	binary.BigEndian.PutUint16(header[4:6], pduRef)
	binary.BigEndian.PutUint16(header[6:8], 2)
	binary.BigEndian.PutUint16(header[8:10], 0)

	param := []byte{fn, 0x00}

	cotpData := append([]byte{0x02, CotpDt, 0x80}, append(header, param...)...)
	s.sendTpkt(conn, cotpData)
}

func (s *S7CommService) sendTpkt(conn net.Conn, cotpPayload []byte) {
	totalLen := uint16(len(cotpPayload) + 4)
	tpkt := make([]byte, 4)
	tpkt[0] = 0x03
	tpkt[1] = 0x00
	binary.BigEndian.PutUint16(tpkt[2:4], totalLen)

	packet := append(tpkt, cotpPayload...)
	conn.Write(packet)
}

func (s *S7CommService) Stop() error {
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}

func (s *S7CommService) Status() string {
	if s.listener != nil {
		return "Running"
	}
	return "Stopped"
}

func (s *S7CommService) Port() int {
	return s.port
}

func (s *S7CommService) Protocol() string {
	return "s7comm"
}

func (s *S7CommService) IsIsolated() bool {
	return s.isoEngine != nil
}

func (s *S7CommService) SetTTL(seconds int) {
	s.ttl = seconds
}

func (s *S7CommService) GetTTL() int {
	return s.ttl
}
