package modbus

import (
	"context"
	"encoding/binary"
	"fmt"
	"honeygo/internal/db"
	"honeygo/internal/isolation"
	"honeygo/internal/misp"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Modbus Function Codes
const (
	FcReadCoils              = 0x01
	FcReadDiscreteInputs     = 0x02
	FcReadHoldingRegisters   = 0x03
	FcReadInputRegisters     = 0x04
	FcWriteSingleCoil        = 0x05
	FcWriteSingleRegister    = 0x06
	FcWriteMultipleRegisters = 0x10
	FcReportServerID         = 0x11
	FcReadDeviceID           = 0x2B
)

type ModbusService struct {
	port      int
	profile   string
	listener  net.Listener
	logger    io.Writer
	isoEngine *isolation.Engine
	ttl       int
	mu        sync.Mutex
	registers map[uint16]uint16
	coils     map[uint16]bool
}

func NewModbusService(port int, profile ...string) *ModbusService {
	prof := "schneider"
	if len(profile) > 0 && profile[0] != "" {
		prof = profile[0]
	}
	s := &ModbusService{
		port:      port,
		profile:   prof,
		ttl:       300,
		registers: make(map[uint16]uint16),
		coils:     make(map[uint16]bool),
	}
	s.applyProfileRegisters()
	return s
}

func (s *ModbusService) SetProfile(profile string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profile = profile
	s.applyProfileRegisters()
	s.log("[green][+] Modbus PLC profile set to: %s[white]", s.profile)
}

func (s *ModbusService) GetProfile() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.profile
}

func (s *ModbusService) applyProfileRegisters() {
	p := strings.ToLower(strings.TrimSpace(s.profile))
	switch {
	case strings.Contains(p, "westinghouse") || strings.Contains(p, "common-q") || strings.Contains(p, "commonq"):
		// Westinghouse Common Q AC160 Nuclear Safety System Registers
		s.registers[0] = 2250   // 40001: RCS Core Pressure (2250 psia)
		s.registers[1] = 5820   // 40002: Core Exit Temp x10 (582.0 F)
		s.registers[2] = 100    // 40003: Reactor Thermal Power % (100%)
		s.registers[3] = 0x0001 // 40004: RPS Reactor Trip Status (1 = ARMED / NORMAL)
		s.registers[4] = 0x0000 // 40005: Containment Spray Actuation (0 = INACTIVE)
		s.registers[5] = 1850   // 40006: Pressurizer Level % x10 (185.0%)
		s.coils[0] = true       // 00001: RPS Channel A Trip Ready
		s.coils[1] = false      // 00002: Manual Scram Tripped

	case strings.Contains(p, "triconex") || strings.Contains(p, "tricon") || strings.Contains(p, "invensys"):
		// Invensys Triconex Tricon 3008 TMR SIL-3 SIS Registers
		s.registers[0] = 0x0003 // 40001: TMR 2oo3 Voter Status (3 Legs Healthy)
		s.registers[1] = 0x0000 // 40002: ESD Emergency Shutdown Trip (0 = Normal)
		s.registers[2] = 1450   // 40003: Flare Header Pressure (1450 kPa)
		s.registers[3] = 0x0001 // 40004: SIS System State (1 = ACTIVE PROTECT)
		s.registers[4] = 720    // 40005: Turbine Vibration mm/s x100 (7.20 mm/s)
		s.registers[5] = 0x0000 // 40006: Deluge Valve Fire Suppression (0 = CLOSED)
		s.coils[0] = true       // 00001: SIS Interlock Armed
		s.coils[1] = false      // 00002: ESD Trip Active

	default:
		// Schneider Electric Modicon M221 Factory Automation PLC Registers
		s.registers[0] = 120   // 40001: Pressure PSI
		s.registers[1] = 450   // 40002: Temp x10 (45.0 C)
		s.registers[2] = 1000  // 40003: Flow Rate L/min
		s.registers[3] = 0x0001 // 40004: PLC Status Running
		s.registers[4] = 0x0000 // 40005: Error Code
		s.coils[0] = true      // 00001: Pump 1 Running
		s.coils[1] = false     // 00002: High Alarm
	}
}

func (s *ModbusService) SetLogger(w io.Writer) {
	s.logger = w
}

func (s *ModbusService) log(format string, a ...interface{}) {
	if s.logger != nil {
		fmt.Fprintf(s.logger, format+"\n", a...)
	}
}

func (s *ModbusService) EnableIsolation(engine *isolation.Engine) {
	s.isoEngine = engine
}

func (s *ModbusService) Start(ctx context.Context) error {
	if s.isoEngine == nil {
		return fmt.Errorf("modbus PLC service requires container isolation (must enable isolation)")
	}
	var err error
	s.listener, err = net.Listen("tcp4", fmt.Sprintf("0.0.0.0:%d", s.port))
	if err != nil {
		return err
	}

	s.log("[green]Modbus TCP Service listening on port %d[white]", s.port)

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

func (s *ModbusService) handleConn(conn net.Conn) {
	defer conn.Close()

	remoteIP := db.ExtractIP(conn.RemoteAddr().String())

	s.log("[orange][!] Modbus TCP connection from %s[white]", remoteIP)

	headerBuf := make([]byte, 7) // MBAP Header size
	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, err := io.ReadFull(conn, headerBuf)
		if err != nil {
			break
		}

		transactionID := binary.BigEndian.Uint16(headerBuf[0:2])
		protocolID := binary.BigEndian.Uint16(headerBuf[2:4])
		length := binary.BigEndian.Uint16(headerBuf[4:6])
		unitID := headerBuf[6]

		if protocolID != 0 {
			// Not Modbus TCP
			break
		}

		if length < 2 {
			break
		}

		pduLen := int(length - 1) // minus UnitID byte
		pduBuf := make([]byte, pduLen)
		_, err = io.ReadFull(conn, pduBuf)
		if err != nil {
			break
		}

		functionCode := pduBuf[0]
		pduData := pduBuf[1:]

		rawHex := fmt.Sprintf("%X", append(headerBuf, pduBuf...))
		db.RecordAttempt(&db.Attempt{
			Protocol: "modbus",
			RemoteIP: remoteIP,
			Port:     s.port,
			RawData:  rawHex,
		})

		s.processRequest(conn, remoteIP, transactionID, unitID, functionCode, pduData)
	}
}

func (s *ModbusService) processRequest(conn net.Conn, remoteIP string, transID uint16, unitID byte, fc byte, data []byte) {
	cmdStr := fmt.Sprintf("Modbus FC=0x%02X UnitID=%d", fc, unitID)

	switch fc {
	case FcReadCoils, FcReadDiscreteInputs:
		if len(data) >= 4 {
			start := binary.BigEndian.Uint16(data[0:2])
			qty := binary.BigEndian.Uint16(data[2:4])
			cmdStr = fmt.Sprintf("Modbus FC=0x%02X ReadCoils Start=%d Qty=%d", fc, start, qty)
			s.sendCoilsResponse(conn, transID, unitID, fc, start, qty)
		}

	case FcReadHoldingRegisters, FcReadInputRegisters:
		if len(data) >= 4 {
			start := binary.BigEndian.Uint16(data[0:2])
			qty := binary.BigEndian.Uint16(data[2:4])
			cmdStr = fmt.Sprintf("Modbus FC=0x%02X ReadRegisters Start=%d Qty=%d", fc, start, qty)
			s.sendRegistersResponse(conn, transID, unitID, fc, start, qty)
		}

	case FcWriteSingleCoil:
		if len(data) >= 4 {
			addr := binary.BigEndian.Uint16(data[0:2])
			val := binary.BigEndian.Uint16(data[2:4]) == 0xFF00
			cmdStr = fmt.Sprintf("Modbus FC=0x05 WriteSingleCoil Addr=%d Val=%t", addr, val)
			s.mu.Lock()
			s.coils[addr] = val
			s.mu.Unlock()
			s.sendEchoResponse(conn, transID, unitID, fc, data[:4])
		}

	case FcWriteSingleRegister:
		if len(data) >= 4 {
			addr := binary.BigEndian.Uint16(data[0:2])
			val := binary.BigEndian.Uint16(data[2:4])
			cmdStr = fmt.Sprintf("Modbus FC=0x06 WriteSingleRegister Addr=%d Val=%d", addr, val)
			s.mu.Lock()
			s.registers[addr] = val
			s.mu.Unlock()
			s.sendEchoResponse(conn, transID, unitID, fc, data[:4])
		}

	case FcWriteMultipleRegisters:
		if len(data) >= 5 {
			start := binary.BigEndian.Uint16(data[0:2])
			qty := binary.BigEndian.Uint16(data[2:4])
			byteCnt := data[4]
			cmdStr = fmt.Sprintf("Modbus FC=0x10 WriteMultipleRegisters Start=%d Qty=%d Bytes=%d", start, qty, byteCnt)
			if len(data) >= 5+int(byteCnt) {
				s.mu.Lock()
				for i := uint16(0); i < qty; i++ {
					val := binary.BigEndian.Uint16(data[5+i*2 : 7+i*2])
					s.registers[start+i] = val
				}
				s.mu.Unlock()
			}
			respData := make([]byte, 4)
			binary.BigEndian.PutUint16(respData[0:2], start)
			binary.BigEndian.PutUint16(respData[2:4], qty)
			s.sendEchoResponse(conn, transID, unitID, fc, respData)
		}

	case FcReportServerID:
		cmdStr = "Modbus FC=0x11 ReportServerID"
		s.sendReportServerIDResponse(conn, transID, unitID)

	case FcReadDeviceID:
		cmdStr = "Modbus FC=0x2B ReadDeviceIdentification"
		s.sendReadDeviceIDResponse(conn, transID, unitID, data)

	default:
		s.sendExceptionResponse(conn, transID, unitID, fc, 0x01) // Illegal Function
	}

	s.log("[red][!] Modbus command executed from %s: %s[white]", remoteIP, cmdStr)
	db.RecordCommand(&db.Command{
		Protocol: "modbus",
		RemoteIP: remoteIP,
		Username: fmt.Sprintf("unit-%d", unitID),
		Command:  cmdStr,
	})
	misp.PushCommand("modbus", remoteIP, fmt.Sprintf("unit-%d", unitID), cmdStr)
}

func (s *ModbusService) sendCoilsResponse(conn net.Conn, transID uint16, unitID byte, fc byte, start uint16, qty uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	byteCount := (qty + 7) / 8
	coilBytes := make([]byte, byteCount)
	for i := uint16(0); i < qty; i++ {
		if s.coils[start+i] {
			coilBytes[i/8] |= (1 << (i % 8))
		}
	}

	pdu := append([]byte{fc, byte(byteCount)}, coilBytes...)
	s.sendFrame(conn, transID, unitID, pdu)
}

func (s *ModbusService) sendRegistersResponse(conn net.Conn, transID uint16, unitID byte, fc byte, start uint16, qty uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()

	byteCount := qty * 2
	regBytes := make([]byte, byteCount)
	for i := uint16(0); i < qty; i++ {
		val := s.registers[start+i]
		binary.BigEndian.PutUint16(regBytes[i*2:(i+1)*2], val)
	}

	pdu := append([]byte{fc, byte(byteCount)}, regBytes...)
	s.sendFrame(conn, transID, unitID, pdu)
}

func (s *ModbusService) getDeviceIdentity() (serverID string, vendor string, product string, revision string) {
	p := strings.ToLower(strings.TrimSpace(s.profile))
	switch {
	case strings.Contains(p, "westinghouse") || strings.Contains(p, "common-q") || strings.Contains(p, "commonq"):
		return "Westinghouse Common Q AC160 PM646 Nuclear Safety Controller v4.2.1",
			"Westinghouse Electric Company LLC",
			"Common Q / AC160 PM646",
			"v4.2.1"
	case strings.Contains(p, "triconex") || strings.Contains(p, "tricon") || strings.Contains(p, "invensys"):
		return "Invensys Triconex Tricon 3008 TMR SIS Safety Controller v10.4.3",
			"Schneider Electric / Triconex",
			"Tricon 3008 TMR SIS",
			"v10.4.3"
	default:
		return "Schneider Electric Modicon M221 PLC v2.10",
			"Schneider Electric",
			"Modicon M221",
			"v2.10"
	}
}

func (s *ModbusService) sendReportServerIDResponse(conn net.Conn, transID uint16, unitID byte) {
	s.mu.Lock()
	serverIDStr, _, _, _ := s.getDeviceIdentity()
	s.mu.Unlock()

	serverID := []byte(serverIDStr)
	pdu := []byte{FcReportServerID, byte(len(serverID) + 1)}
	pdu = append(pdu, serverID...)
	pdu = append(pdu, 0xFF) // Run Indicator Status: ON
	s.sendFrame(conn, transID, unitID, pdu)
}

func (s *ModbusService) sendReadDeviceIDResponse(conn net.Conn, transID uint16, unitID byte, data []byte) {
	s.mu.Lock()
	_, vendor, product, revision := s.getDeviceIdentity()
	s.mu.Unlock()

	pdu := []byte{
		FcReadDeviceID, 0x0E, // MEI Type
		0x01, // ReadDeviceID code (basic)
		0x81, // Conformity level (stream + individual)
		0x00, // More follows
		0x00, // Next object ID
		0x03, // Number of objects
		0x00, byte(len(vendor)),
	}
	pdu = append(pdu, []byte(vendor)...)
	pdu = append(pdu, 0x01, byte(len(product)))
	pdu = append(pdu, []byte(product)...)
	pdu = append(pdu, 0x02, byte(len(revision)))
	pdu = append(pdu, []byte(revision)...)

	s.sendFrame(conn, transID, unitID, pdu)
}

func (s *ModbusService) sendEchoResponse(conn net.Conn, transID uint16, unitID byte, fc byte, payload []byte) {
	pdu := append([]byte{fc}, payload...)
	s.sendFrame(conn, transID, unitID, pdu)
}

func (s *ModbusService) sendExceptionResponse(conn net.Conn, transID uint16, unitID byte, fc byte, excCode byte) {
	pdu := []byte{fc | 0x80, excCode}
	s.sendFrame(conn, transID, unitID, pdu)
}

func (s *ModbusService) sendFrame(conn net.Conn, transID uint16, unitID byte, pdu []byte) {
	length := uint16(len(pdu) + 1) // +1 for UnitID
	header := make([]byte, 7)
	binary.BigEndian.PutUint16(header[0:2], transID)
	binary.BigEndian.PutUint16(header[2:4], 0) // Protocol ID
	binary.BigEndian.PutUint16(header[4:6], length)
	header[6] = unitID

	frame := append(header, pdu...)
	conn.Write(frame)
}

func (s *ModbusService) Stop() error {
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}

func (s *ModbusService) Status() string {
	if s.listener != nil {
		return "Running"
	}
	return "Stopped"
}

func (s *ModbusService) Port() int {
	return s.port
}

func (s *ModbusService) Protocol() string {
	return "modbus"
}

func (s *ModbusService) IsIsolated() bool {
	return s.isoEngine != nil
}

func (s *ModbusService) SetTTL(seconds int) {
	s.ttl = seconds
}

func (s *ModbusService) GetTTL() int {
	return s.ttl
}
