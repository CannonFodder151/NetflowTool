package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gosnmp/gosnmp"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

// ─── MODELS ──────────────────────────────────────────────────────────────────

type User struct {
	ID                int64      `json:"id"`
	Username          string     `json:"username"`
	PasswordHash      string     `json:"-"`
	IsAdmin           bool       `json:"is_admin"`
	MustResetPassword bool       `json:"must_reset_password"`
	CreatedAt         time.Time  `json:"created_at"`
	LastLogin         *time.Time `json:"last_login"`
}

type FlowRecord struct {
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
	Protocol      uint8
	Bytes         uint64
	Packets       uint32
	InputIface    uint32
	OutputIface   uint32
	DeviceIP      string
	FirstSwitched time.Time
	LastSwitched  time.Time
	CollectedAt   time.Time
}

type SNMPDevice struct {
	ID            int64      `json:"id"`
	Name          string     `json:"name"`
	IP            string     `json:"ip"`
	SNMPVersion   string     `json:"snmp_version"`
	Community     string     `json:"community,omitempty"`
	SecurityLevel string     `json:"security_level,omitempty"`
	SnmpUsername  string     `json:"snmp_username,omitempty"`
	AuthProto     string     `json:"auth_proto,omitempty"`
	AuthPass      string     `json:"auth_pass,omitempty"`
	PrivProto     string     `json:"priv_proto,omitempty"`
	PrivPass      string     `json:"priv_pass,omitempty"`
	PollInterval  int        `json:"poll_interval"`
	Enabled       bool       `json:"enabled"`
	LastPoll      string `json:"last_poll"`
}

type IfaceView struct {
	ID            int64  `json:"id"`
	DeviceID      int64  `json:"device_id"`
	DeviceName    string `json:"device_name"`
	DeviceIP      string `json:"device_ip"`
	Idx           int    `json:"idx"`
	Name          string `json:"name"`
	Description   string `json:"description"`
	Speed         uint64 `json:"speed"`
	AdminStatus   int    `json:"admin_status"`
	OperStatus    int    `json:"oper_status"`
	InOctets      uint64 `json:"in_octets"`
	OutOctets     uint64 `json:"out_octets"`
	InErrors      uint64 `json:"in_errors"`
	OutErrors     uint64 `json:"out_errors"`
	LastUpdated   string `json:"last_updated"`
}

type FLog struct {
	ID         int64  `json:"id"`
	Timestamp  string `json:"timestamp"`
	DeviceName string `json:"device_name"`
	DeviceIP   string `json:"device_ip"`
	LogType    string `json:"log_type"`
	Action     string `json:"action"`
	Message    string `json:"message"`
	SrcIP      string `json:"src_ip"`
	DstIP      string `json:"dst_ip"`
	Service    string `json:"service"`
	RiskLevel  string `json:"risk_level"`
	RawLog     string `json:"raw_log"`
}

type Tile struct {
	ID       int64  `json:"id"`
	UserID   int64  `json:"user_id"`
	Type     string `json:"type"`
	Title    string `json:"title"`
	Config   string `json:"config"`
	PosX     int    `json:"pos_x"`
	PosY     int    `json:"pos_y"`
	Width    int    `json:"width"`
	Height   int    `json:"height"`
}

// ─── DATABASE ────────────────────────────────────────────────────────────────

type DB struct {
	*sql.DB
	mu sync.Mutex
}

func openDB(path string) (*DB, error) {
	conn, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	if err = conn.Ping(); err != nil {
		return nil, err
	}
	d := &DB{DB: conn}
	if err = d.migrate(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *DB) migrate() error {
	tx, _ := d.Begin()
	defer tx.Rollback()

	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			is_admin INTEGER DEFAULT 0,
			must_reset_password INTEGER DEFAULT 1,
			created_at TEXT DEFAULT (datetime('now')),
			last_login TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS flow_records (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			src_ip TEXT, dst_ip TEXT, src_port INTEGER, dst_port INTEGER,
			protocol INTEGER, bytes INTEGER, packets INTEGER,
			input_iface INTEGER, output_iface INTEGER,
			device_ip TEXT, first_switched TEXT, last_switched TEXT,
			collected_at TEXT DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS snmp_devices (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT, ip TEXT UNIQUE NOT NULL, snmp_version TEXT,
			community TEXT DEFAULT 'public', security_level TEXT,
			snmp_username TEXT, auth_proto TEXT, auth_pass TEXT,
			priv_proto TEXT, priv_pass TEXT,
			poll_interval INTEGER DEFAULT 60, enabled INTEGER DEFAULT 1,
			last_poll TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS interfaces (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			device_id INTEGER, idx INTEGER, name TEXT, descr TEXT,
			speed INTEGER, admin_status INTEGER, oper_status INTEGER,
			in_octets INTEGER, out_octets INTEGER,
			in_errors INTEGER, out_errors INTEGER, last_updated TEXT,
			FOREIGN KEY(device_id) REFERENCES snmp_devices(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS fortigate_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ts TEXT, device_name TEXT, device_ip TEXT, log_type TEXT,
			action TEXT, message TEXT, src_ip TEXT, dst_ip TEXT,
			service TEXT, risk_level TEXT, raw_log TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS dashboard_tiles (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_id INTEGER, tile_type TEXT, title TEXT, config TEXT DEFAULT '{}',
			pos_x INTEGER DEFAULT 0, pos_y INTEGER DEFAULT 0,
			width INTEGER DEFAULT 4, height INTEGER DEFAULT 3,
			FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS meta (
			key TEXT PRIMARY KEY,
			value TEXT
		)`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}

	for _, idx := range []string{
		`CREATE INDEX IF NOT EXISTS idx_flow_ts ON flow_records(collected_at)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_src ON flow_records(src_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_flow_dst ON flow_records(dst_ip)`,
		`CREATE INDEX IF NOT EXISTS idx_log_ts ON fortigate_logs(ts)`,
		`CREATE INDEX IF NOT EXISTS idx_log_risk ON fortigate_logs(risk_level)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_iface_device ON interfaces(device_id,idx)`,
	} {
		tx.Exec(idx)
	}

	tx.Commit()

	// seed admin
	var cnt int
	d.QueryRow("SELECT COUNT(*) FROM users WHERE username='admin'").Scan(&cnt)
	if cnt == 0 {
		h, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		d.Exec("INSERT INTO users (username,password_hash,is_admin,must_reset_password) VALUES (?,?,1,1)", "admin", string(h))
	}

	return nil
}

// ─── AUTH ────────────────────────────────────────────────────────────────────

var jwtSecret = func() []byte {
	s := os.Getenv("JWT_SECRET")
	if s == "" {
		s = "netflow-secret-change-in-prod"
	}
	return []byte(s)
}()

type Claims struct {
	UserID   int64  `json:"uid"`
	Username string `json:"uname"`
	IsAdmin  bool   `json:"admin"`
	Exp      int64  `json:"exp"`
}

func makeToken(userID int64, username string, isAdmin bool) string {
	h := hmac.New(sha256.New, jwtSecret)
	exp := time.Now().Add(24 * time.Hour).Unix()
	raw := fmt.Sprintf("%d|%s|%v|%d", userID, username, isAdmin, exp)
	h.Write([]byte(raw))
	sig := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return base64.URLEncoding.EncodeToString([]byte(raw)) + "." + sig
}

func parseToken(token string) *Claims {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil
	}

	raw, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil
	}

	h := hmac.New(sha256.New, jwtSecret)
	h.Write(raw)
	expect := base64.URLEncoding.EncodeToString(h.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expect)) {
		return nil
	}

	fields := strings.SplitN(string(raw), "|", 4)
	if len(fields) != 4 {
		return nil
	}

	userID, _ := strconv.ParseInt(fields[0], 10, 64)
	exp, _ := strconv.ParseInt(fields[3], 10, 64)
	if time.Now().Unix() > exp {
		return nil
	}

	return &Claims{
		UserID:   userID,
		Username: fields[1],
		IsAdmin:  fields[2] == "true",
		Exp:      exp,
	}
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ah := r.Header.Get("Authorization")
		if !strings.HasPrefix(ah, "Bearer ") {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		c := parseToken(ah[7:])
		if c == nil {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}
		r.Header.Set("X-User-ID", fmt.Sprintf("%d", c.UserID))
		r.Header.Set("X-Username", c.Username)
		r.Header.Set("X-Is-Admin", fmt.Sprintf("%v", c.IsAdmin))
		next(w, r)
	}
}

func adminMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Is-Admin") != "true" {
			http.Error(w, `{"error":"admin required"}`, http.StatusForbidden)
			return
		}
		next(w, r)
	})
}

// ─── PORT CATEGORIZATION ─────────────────────────────────────────────────────

var portServices = map[uint16]string{
	20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
	53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 123: "NTP",
	135: "MS-RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
	162: "SNMP-Trap", 389: "LDAP", 443: "HTTPS", 445: "SMB",
	465: "SMTPS", 500: "IKE", 514: "Syslog", 587: "SMTP-Sub",
	636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1194: "OpenVPN",
	1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
	5900: "VNC", 8080: "HTTP-Proxy", 8443: "HTTPS-Proxy",
	10000: "Webmin", 20000: "DNP", 4500: "IKE-NAT",
}

func categorizePort(port uint16) string {
	if s, ok := portServices[port]; ok {
		return s
	}
	return fmt.Sprintf("Port-%d", port)
}

// validateTimeRange ensures only safe SQLite time expressions are used
var validRanges = map[string]bool{
	"1h": true, "2h": true, "6h": true, "12h": true, "24h": true,
	"7d": true, "14d": true, "30d": true, "90d": true,
}

func safeTimeRange(rng string) string {
	if validRanges[rng] {
		return rng
	}
	return "1h"
}

// ─── NETFLOW COLLECTOR ───────────────────────────────────────────────────────

type nfTemplate struct {
	fields []struct {
		typ uint16
		len uint16
	}
}

var templateCache = struct {
	sync.Mutex
	m map[string]*nfTemplate
}{m: make(map[string]*nfTemplate)}

func tplKey(device string, sourceID uint32, tplID uint16) string {
	return fmt.Sprintf("%s|%d|%d", device, sourceID, tplID)
}

func startNetflow(db *DB, port int) {
	addr := net.UDPAddr{Port: port}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("netflow listen: %v", err)
	}
	defer conn.Close()
	log.Printf("NetFlow v9/IPFIX listening UDP %d", port)

	buf := make([]byte, 65535)
	var pktCount int
	lastLog := time.Now()
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		pktCount++
		if time.Since(lastLog) > 15*time.Second {
			lastLog = time.Now()
			log.Printf("[NETFLOW] %d packets received in last 15s (latest from %s, %d bytes)", pktCount, src.IP, n)
			pktCount = 0
		}
		go handleFlowPacket(buf[:n], db, src.IP.String())
	}
}

func handleFlowPacket(data []byte, db *DB, deviceIP string) {
	if len(data) < 16 {
		return
	}
	ver := binary.BigEndian.Uint16(data[:2])
	if ver == 9 {
		parseV9(data, db, deviceIP)
	} else if ver == 10 {
		parseV10(data, db, deviceIP)
	}
}

func parseV9(data []byte, db *DB, deviceIP string) {
	if len(data) < 20 {
		return
	}
	count := binary.BigEndian.Uint16(data[2:4])
	unixSecs := binary.BigEndian.Uint32(data[8:12])
	sourceID := binary.BigEndian.Uint32(data[16:20])
	payload := data[20:]
	var flows []FlowRecord
	collected := time.Unix(int64(unixSecs), 0).UTC()

	for i := 0; i < int(count) && len(payload) >= 4; i++ {
		fsID := binary.BigEndian.Uint16(payload[:2])
		fsLen := binary.BigEndian.Uint16(payload[2:4])
		if fsLen < 4 || int(fsLen) > len(payload) {
			break
		}
		fsData := payload[4:fsLen]

		switch {
		case fsID == 0: // Template FlowSet
			parseTemplates(fsData, deviceIP, sourceID)
		case fsID == 1: // Options Template - ignore
		case fsID > 255: // Data FlowSet
			tpl := getTemplate(deviceIP, sourceID, fsID)
			if tpl != nil && len(tpl.fields) > 0 {
				flows = append(flows, parseDataFlow(fsData, tpl, collected)...)
			}
		}
		payload = payload[fsLen:]
	}

	if len(flows) > 0 {
		insertFlows(db, flows)
		log.Printf("[NETFLOW] v9 from %s: parsed %d flows (total now inserted this packet)", deviceIP, len(flows))
	}
}

func parseV10(data []byte, db *DB, deviceIP string) {
	// IPFIX header: version(2) length(2) exportTime(4) seq(4) domainID(4)
	if len(data) < 16 {
		return
	}
	exportTime := binary.BigEndian.Uint32(data[4:8])
	domainID := binary.BigEndian.Uint32(data[12:16])
	payload := data[16:]
	var flows []FlowRecord
	collected := time.Unix(int64(exportTime), 0).UTC()

	for len(payload) >= 4 {
		fsID := binary.BigEndian.Uint16(payload[:2])
		fsLen := binary.BigEndian.Uint16(payload[2:4])
		if fsLen < 4 || int(fsLen) > len(payload) {
			break
		}
		fsData := payload[4:fsLen]

		switch {
		case fsID == 2: // Template FlowSet (IPFIX)
			parseTemplates(fsData, deviceIP, domainID)
		case fsID == 3: // Options Template - ignore
		case fsID > 255: // Data FlowSet
			tpl := getTemplate(deviceIP, domainID, fsID)
			if tpl != nil && len(tpl.fields) > 0 {
				flows = append(flows, parseDataFlow(fsData, tpl, collected)...)
			}
		}
		payload = payload[fsLen:]
	}

	if len(flows) > 0 {
		insertFlows(db, flows)
		log.Printf("[NETFLOW] v10 from %s: parsed %d flows", deviceIP, len(flows))
	}
}

func parseTemplates(fsData []byte, device string, sourceID uint32) {
	for len(fsData) >= 4 {
		tplID := binary.BigEndian.Uint16(fsData[:2])
		fieldCount := binary.BigEndian.Uint16(fsData[2:4])
		if tplID < 256 || fieldCount == 0 || len(fsData) < 4+int(fieldCount)*4 {
			return
		}
		tpl := &nfTemplate{}
		for i := 0; i < int(fieldCount); i++ {
			off := 4 + i*4
			typ := binary.BigEndian.Uint16(fsData[off : off+2])
			ln := binary.BigEndian.Uint16(fsData[off+2 : off+4])
			tpl.fields = append(tpl.fields, struct {
				typ uint16
				len uint16
			}{typ, ln})
		}
		templateCache.Lock()
		templateCache.m[tplKey(device, sourceID, tplID)] = tpl
		templateCache.Unlock()
		fsData = fsData[4+int(fieldCount)*4:]
	}
}

func getTemplate(device string, sourceID uint32, tplID uint16) *nfTemplate {
	templateCache.Lock()
	defer templateCache.Unlock()
	return templateCache.m[tplKey(device, sourceID, tplID)]
}

func parseDataFlow(fsData []byte, tpl *nfTemplate, collected time.Time) []FlowRecord {
	recLen := 0
	for _, f := range tpl.fields {
		recLen += int(f.len)
	}
	if recLen == 0 {
		return nil
	}
	var flows []FlowRecord
	for off := 0; off+recLen <= len(fsData); off += recLen {
		rec := fsData[off : off+recLen]
		fr := FlowRecord{CollectedAt: collected, FirstSwitched: collected, LastSwitched: collected}
		pos := 0
		for _, f := range tpl.fields {
			if pos+int(f.len) > recLen {
				break
			}
			val := rec[pos : pos+int(f.len)]
			switch f.typ {
			case 1, 230: // IN_BYTES / octetDeltaCount
				fr.Bytes = fieldUint(val)
			case 2, 231: // IN_PKTS / packetDeltaCount
				fr.Packets = uint32(fieldUint(val))
			case 4, 98: // PROTOCOL
				if len(val) >= 1 {
					fr.Protocol = val[0]
				}
			case 7, 239: // L4_SRC_PORT
				fr.SrcPort = uint16(fieldUint(val))
			case 8, 225: // IPV4_SRC_ADDR
				if len(val) >= 4 {
					fr.SrcIP = fmt.Sprintf("%d.%d.%d.%d", val[0], val[1], val[2], val[3])
				}
			case 10, 240: // INPUT_SNMP (ingress interface)
				fr.InputIface = uint32(fieldUint(val))
			case 11, 241: // L4_DST_PORT
				fr.DstPort = uint16(fieldUint(val))
			case 12, 226: // IPV4_DST_ADDR
				if len(val) >= 4 {
					fr.DstIP = fmt.Sprintf("%d.%d.%d.%d", val[0], val[1], val[2], val[3])
				}
			case 14, 243: // OUTPUT_SNMP (egress interface)
				fr.OutputIface = uint32(fieldUint(val))
			case 21, 153: // LAST_SWITCHED
			case 22, 152: // FIRST_SWITCHED
			}
			pos += int(f.len)
		}
		if fr.SrcIP != "" || fr.DstIP != "" {
			flows = append(flows, fr)
		}
	}
	return flows
}

func fieldUint(b []byte) uint64 {
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v
}

func insertFlows(db *DB, flows []FlowRecord) {
	if db == nil {
		return
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare("INSERT INTO flow_records (src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,input_iface,output_iface,device_ip,first_switched,last_switched,collected_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
	if err != nil {
		return
	}
	defer stmt.Close()
	for _, f := range flows {
		stmt.Exec(f.SrcIP, f.DstIP, f.SrcPort, f.DstPort, f.Protocol, f.Bytes, f.Packets,
			f.InputIface, f.OutputIface, f.DeviceIP,
			f.FirstSwitched.UTC().Format("2006-01-02 15:04:05"),
			f.LastSwitched.UTC().Format("2006-01-02 15:04:05"),
			f.CollectedAt.UTC().Format("2006-01-02 15:04:05"))
	}
	tx.Commit()
}

// ─── SNMP POLLER ─────────────────────────────────────────────────────────────

func startSNMPPoller(db *DB) {
	for {
		devices, err := getDevices(db, true)
		if err != nil {
			log.Printf("SNMP poller: %v", err)
			time.Sleep(30 * time.Second)
			continue
		}
		for _, d := range devices {
			snmpScan(db, d.ID, nil)
		}
		time.Sleep(60 * time.Second)
	}
}

func getDevices(db *DB, enabled bool) ([]SNMPDevice, error) {
	rows, err := db.Query(`SELECT id,name,ip,snmp_version,community,security_level,snmp_username,auth_proto,auth_pass,priv_proto,priv_pass,poll_interval,enabled,last_poll
		FROM snmp_devices WHERE enabled=?`, enabled)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []SNMPDevice
	for rows.Next() {
		d := SNMPDevice{}
		var lp sql.NullString
		if err := rows.Scan(&d.ID, &d.Name, &d.IP, &d.SNMPVersion, &d.Community, &d.SecurityLevel,
			&d.SnmpUsername, &d.AuthProto, &d.AuthPass, &d.PrivProto, &d.PrivPass,
			&d.PollInterval, &d.Enabled, &lp); err != nil {
			continue
		}
		d.LastPoll = lp.String
		devices = append(devices, d)
	}
	return devices, nil
}

// snmpScan polls a single device and stores all interface data
// Returns a debug object describing what happened
func snmpScanWithResult(db *DB, deviceID int64) map[string]interface{} {
	debug := map[string]interface{}{
		"device_id":   deviceID,
		"started":     time.Now().UTC().Format("2006-01-02 15:04:05"),
		"status":      "running",
		"interfaces":  0,
		"raw_samples": []string{},
		"errors":      []string{},
	}
	err := snmpScan(db, deviceID, debug)
	if err != nil {
		debug["status"] = "error"
		debug["errors"] = append(debug["errors"].([]string), err.Error())
	} else {
		debug["status"] = "success"
	}
	debug["finished"] = time.Now().UTC().Format("2006-01-02 15:04:05")
	return debug
}

func snmpScan(db *DB, deviceID int64, debug map[string]interface{}) error {
	var d SNMPDevice
	var lp sql.NullString
	err := db.QueryRow(`SELECT id,name,ip,snmp_version,community,security_level,snmp_username,auth_proto,auth_pass,priv_proto,priv_pass,poll_interval,enabled,last_poll
		FROM snmp_devices WHERE id=?`, deviceID).
		Scan(&d.ID, &d.Name, &d.IP, &d.SNMPVersion, &d.Community, &d.SecurityLevel,
			&d.SnmpUsername, &d.AuthProto, &d.AuthPass, &d.PrivProto, &d.PrivPass,
			&d.PollInterval, &d.Enabled, &lp)
	d.LastPoll = lp.String
	if err != nil {
		return fmt.Errorf("device %d not found: %v", deviceID, err)
	}

	if debug != nil {
		debug["device_name"] = d.Name
		debug["device_ip"] = d.IP
		debug["snmp_version"] = d.SNMPVersion
		if d.SNMPVersion == "v3" {
			debug["security_level"] = d.SecurityLevel
			debug["auth_proto"] = d.AuthProto
			debug["priv_proto"] = d.PrivProto
		} else {
			debug["community"] = d.Community
		}
	}

	sn := &gosnmp.GoSNMP{
		Target:    d.IP,
		Port:      161,
		Community: d.Community,
		Version:   gosnmp.Version2c,
		Timeout:   5 * time.Second,
		Retries:   2,
	}

	if d.SNMPVersion == "v3" {
		sn.Version = gosnmp.Version3
		sn.SecurityModel = gosnmp.UserSecurityModel
		sn.MsgFlags = gosnmp.AuthNoPriv
		sn.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName: d.SnmpUsername,
		}
		if d.SecurityLevel == "authPriv" || d.SecurityLevel == "authNoPriv" {
			sn.MsgFlags = gosnmp.AuthNoPriv
			switch d.AuthProto {
			case "MD5":
				sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthenticationProtocol = gosnmp.MD5
			case "SHA224":
				sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthenticationProtocol = gosnmp.SHA224
			case "SHA256":
				sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthenticationProtocol = gosnmp.SHA256
			case "SHA384":
				sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthenticationProtocol = gosnmp.SHA384
			case "SHA512":
				sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthenticationProtocol = gosnmp.SHA512
			default:
				sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthenticationProtocol = gosnmp.SHA
			}
			sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).AuthenticationPassphrase = d.AuthPass
		}
		if d.SecurityLevel == "authPriv" {
			sn.MsgFlags = gosnmp.AuthPriv
			switch d.PrivProto {
			case "AES":
				sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).PrivacyProtocol = gosnmp.AES
			case "AES192":
				sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).PrivacyProtocol = gosnmp.AES192
			case "AES256":
				sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).PrivacyProtocol = gosnmp.AES256
			default:
				sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).PrivacyProtocol = gosnmp.DES
			}
			sn.SecurityParameters.(*gosnmp.UsmSecurityParameters).PrivacyPassphrase = d.PrivPass
		}
	}

	if err := sn.Connect(); err != nil {
		if debug != nil {
			debug["errors"] = append(debug["errors"].([]string), "connect failed: "+err.Error())
		}
		return fmt.Errorf("SNMP connect %s: %v", d.IP, err)
	}
	defer sn.Conn.Close()
	if debug != nil {
		debug["connect"] = "connected to " + d.IP + ":161"
	}

	// Get device info
	oids := []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.5.0", // sysName
	}
	sysInfo, err := sn.Get(oids)
	if err != nil {
		if debug != nil {
			debug["errors"] = append(debug["errors"].([]string), "sysinfo get failed: "+err.Error())
		}
		return fmt.Errorf("SNMP get %s: %v", d.IP, err)
	}
	if debug != nil {
		debug["sysname"] = fmt.Sprintf("%v", sysInfo.Variables[0].Value)
		debug["sysdescr"] = fmt.Sprintf("%v", sysInfo.Variables[1].Value)
	}
	for i, v := range sysInfo.Variables {
		if v.Value == nil {
			continue
		}
		if str, ok := v.Value.(string); ok && str != "" {
			if i == 0 {
				db.Exec("UPDATE snmp_devices SET name=? WHERE id=? AND name=''", str, d.ID)
			} else if i == 1 {
				db.Exec("UPDATE snmp_devices SET name=? WHERE id=? AND (name='' OR name IS NULL)", str, d.ID)
			}
		} else if str := toStr(v.Value); str != "" {
			if i == 0 {
				db.Exec("UPDATE snmp_devices SET name=? WHERE id=? AND name=''", str, d.ID)
			} else if i == 1 {
				db.Exec("UPDATE snmp_devices SET name=? WHERE id=? AND (name='' OR name IS NULL)", str, d.ID)
			}
		}
	}

	// Get ifNumber first
	ifNumRes, err := sn.Get([]string{"1.3.6.1.2.1.2.1.0"})
	if err != nil {
		if debug != nil {
			debug["errors"] = append(debug["errors"].([]string), "ifNumber get failed: "+err.Error())
		}
		return fmt.Errorf("SNMP ifNumber on %s: %v", d.IP, err)
	}
	ifNumber, _ := toInt(ifNumRes.Variables[0].Value)
	if ifNumber < 1 || ifNumber > 1024 {
		ifNumber = 64
	}
	log.Printf("[SNMP] %s has %d interfaces", d.IP, ifNumber)
	if debug != nil {
		debug["ifnumber"] = ifNumber
	}

	type ifData struct {
		idx    int
		name   string
		speed  uint64
		admin  int
		oper   int
		inOct  uint64
		outOct uint64
		inErr  uint64
		outErr uint64
	}
	ifaces := make(map[int]*ifData)
	for i := 1; i <= ifNumber; i++ {
		ifaces[i] = &ifData{idx: i}
	}

	// Per-interface Get: 8 OIDs per request - small, reliable on all agents
	ifCols := []struct {
		oid  string
		col  int
	}{
		{"1.3.6.1.2.1.2.2.1.2", 2},
		{"1.3.6.1.2.1.2.2.1.5", 5},
		{"1.3.6.1.2.1.2.2.1.7", 7},
		{"1.3.6.1.2.1.2.2.1.8", 8},
		{"1.3.6.1.2.1.2.2.1.10", 10},
		{"1.3.6.1.2.1.2.2.1.16", 16},
		{"1.3.6.1.2.1.2.2.1.14", 14},
		{"1.3.6.1.2.1.2.2.1.20", 20},
	}
	colsByName := map[string]int{}
	for _, c := range ifCols {
		colsByName[c.oid] = c.col
	}

	for i := 1; i <= ifNumber; i++ {
		var oids []string
		for _, c := range ifCols {
			oids = append(oids, fmt.Sprintf("%s.%d", c.oid, i))
		}
		res, err := sn.Get(oids)
		if err != nil {
			log.Printf("[SNMP] if%d get failed: %v", i, err)
			if debug != nil {
				debug["errors"] = append(debug["errors"].([]string), fmt.Sprintf("if%d: %v", i, err))
			}
			continue
		}
		// dump the raw response for interface 1 to diagnose value parsing
		if i == 1 {
			log.Printf("[SNMP] if1 raw response (%d vars):", len(res.Variables))
			for _, v := range res.Variables {
				log.Printf("  [SNMP]   %s type=%d value=%v (%T)", v.Name, v.Type, v.Value, v.Value)
			}
		}
		f := ifaces[i]
		for _, v := range res.Variables {
			col, ok := colsByName[oidWithoutIndex(v.Name)]
			if !ok {
				continue
			}
			// log raw values for the first interface to diagnose
			if i == 1 && debug != nil && len(debug["raw_samples"].([]string)) < 12 {
				debug["raw_samples"] = append(debug["raw_samples"].([]string),
					fmt.Sprintf("%s = %v (%T)", v.Name, v.Value, v.Value))
			}
			switch col {
			case 2:
				f.name = toStr(v.Value)
			case 5:
				f.speed, _ = toUint64(v.Value)
			case 7:
				if u, ok := toUint64(v.Value); ok { f.admin = int(u) }
			case 8:
				if u, ok := toUint64(v.Value); ok { f.oper = int(u) }
			case 10:
				f.inOct, _ = toUint64(v.Value)
			case 16:
				f.outOct, _ = toUint64(v.Value)
			case 14:
				f.inErr, _ = toUint64(v.Value)
			case 20:
				f.outErr, _ = toUint64(v.Value)
			}
		}
	}

	if debug != nil {
		debug["interfaces"] = len(ifaces)
	}
	log.Printf("[SNMP] scanned %s: %d interfaces collected", d.IP, len(ifaces))

	// Save all interfaces (manual update-or-insert)
	saved := 0
	savedErrs := []string{}
	for _, f := range ifaces {
		if f.name == "" {
			f.name = fmt.Sprintf("if-%d", f.idx)
		}
		db.mu.Lock()
		var exists int
		db.QueryRow("SELECT COUNT(*) FROM interfaces WHERE device_id=? AND idx=?", d.ID, f.idx).Scan(&exists)
		var err error
		if exists > 0 {
			_, err = db.Exec(`UPDATE interfaces SET name=?, speed=?, admin_status=?, oper_status=?, in_octets=?, out_octets=?, in_errors=?, out_errors=?, last_updated=datetime('now')
				WHERE device_id=? AND idx=?`,
				f.name, f.speed, f.admin, f.oper, f.inOct, f.outOct, f.inErr, f.outErr, d.ID, f.idx)
		} else {
			_, err = db.Exec(`INSERT INTO interfaces (device_id,idx,name,speed,admin_status,oper_status,in_octets,out_octets,in_errors,out_errors,last_updated)
				VALUES (?,?,?,?,?,?,?,?,?,?,datetime('now'))`,
				d.ID, f.idx, f.name, f.speed, f.admin, f.oper, f.inOct, f.outOct, f.inErr, f.outErr)
		}
		if err != nil {
			savedErrs = append(savedErrs, f.name+": "+err.Error())
		} else {
			saved++
		}
		db.mu.Unlock()
	}
	if debug != nil {
		debug["saved"] = saved
		if len(savedErrs) > 0 {
			debug["errors"] = append(debug["errors"].([]string), savedErrs...)
		}
	}

	db.Exec("UPDATE snmp_devices SET last_poll=datetime('now') WHERE id=?", d.ID)
	log.Printf("SNMP scan %s (%s): %d interfaces collected", d.Name, d.IP, len(ifaces))
	return nil
}

func oidWithoutIndex(name string) string {
	lastDot := strings.LastIndex(name, ".")
	if lastDot < 0 {
		return name
	}
	return name[:lastDot]
}

func oidIndex(name string) int {
	lastDot := strings.LastIndex(name, ".")
	if lastDot < 0 {
		return 0
	}
	idx, err := strconv.Atoi(name[lastDot+1:])
	if err != nil || idx < 1 {
		return 0
	}
	return idx
}

func toInt(v interface{}) (int, bool) {
	u, ok := toUint64(v)
	return int(u), ok
}

func toStr(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case []byte:
		return string(t)
	case fmt.Stringer:
		return t.String()
	}
	return ""
}

func toUint64(v interface{}) (uint64, bool) {
	switch t := v.(type) {
	case int:
		return uint64(t), true
	case uint:
		return uint64(t), true
	case uint32:
		return uint64(t), true
	case uint64:
		return t, true
	case int32:
		return uint64(t), true
	case int64:
		return uint64(t), true
	case []byte:
		if len(t) == 4 {
			return uint64(binary.BigEndian.Uint32(t)), true
		}
		if len(t) == 8 {
			return binary.BigEndian.Uint64(t), true
		}
	}
	return 0, false
}

// ─── SYSLOG SERVER ───────────────────────────────────────────────────────────

func startSyslog(db *DB, port int) {
	go func() {
		addr := net.UDPAddr{Port: port}
		conn, err := net.ListenUDP("udp", &addr)
		if err != nil {
			log.Printf("syslog udp: %v", err)
			return
		}
		defer conn.Close()
		log.Printf("Syslog UDP listening %d", port)
		buf := make([]byte, 65535)
		for {
			n, _, _ := conn.ReadFromUDP(buf)
			go processSyslog(buf[:n], db)
		}
	}()

	go func() {
		addr := net.TCPAddr{Port: port}
		ln, err := net.ListenTCP("tcp", &addr)
		if err != nil {
			log.Printf("syslog tcp: %v", err)
			return
		}
		defer ln.Close()
		log.Printf("Syslog TCP listening %d", port)
		for {
			c, _ := ln.Accept()
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 65535)
				for {
					n, err := conn.Read(buf)
					if err != nil {
						return
					}
					processSyslog(buf[:n], db)
				}
			}(c)
		}
	}()
}

func processSyslog(data []byte, db *DB) {
	msg := strings.TrimSpace(string(data))
	if msg == "" {
		return
	}

	entry := parseFLog(msg)
	if entry != nil {
		db.mu.Lock()
		db.Exec(`INSERT INTO fortigate_logs (ts,device_name,device_ip,log_type,action,message,src_ip,dst_ip,service,risk_level,raw_log)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			entry.Timestamp, entry.DeviceName, entry.DeviceIP, entry.LogType, entry.Action,
			entry.Message, entry.SrcIP, entry.DstIP, entry.Service, entry.RiskLevel, entry.RawLog)
		db.mu.Unlock()
	} else {
		log.Printf("syslog: unparsed message (first 200 chars): %s", msg[:min(200, len(msg))])
	}
}

func min(a, b int) int {
	if a < b { return a }
	return b
}

func parseFLog(msg string) *FLog {
	// Strip syslog PRI prefix like <189>
	msg = strings.TrimLeft(msg, "<")
	if idx := strings.IndexByte(msg, '>'); idx >= 0 && idx < 4 {
		if _, err := strconv.Atoi(msg[:idx]); err == nil {
			msg = msg[idx+1:]
		}
	}

	// Locate start of FortiGate data: key=value format starts with date=,
	// CEF format starts with CEF:
	start := -1
	if cef := strings.Index(msg, "CEF:"); cef >= 0 {
		start = cef
	} else if d := strings.Index(msg, "date="); d >= 0 {
		start = d
	}
	if start < 0 {
		return nil // not a FortiGate-style message
	}
	msg = msg[start:]

	fl := &FLog{
		Timestamp: time.Now().UTC().Format("2006-01-02 15:04:05"),
		RawLog:    msg,
		RiskLevel: "low",
	}

	kv := parseKV(msg)
	if t, ok := kv["date"]; ok {
		if tm, ok2 := kv["time"]; ok2 {
			fl.Timestamp = t + " " + tm
		} else {
			fl.Timestamp = t
		}
	}
	if v, ok := kv["devname"]; ok {
		fl.DeviceName = v
	}
	if v, ok := kv["devid"]; ok {
		fl.DeviceIP = v
	}
	if v, ok := kv["type"]; ok {
		fl.LogType = v
	}
	if v, ok := kv["action"]; ok {
		fl.Action = v
	} else if v, ok := kv["status"]; ok {
		fl.Action = v
	}
	if v, ok := kv["srcip"]; ok {
		fl.SrcIP = v
	} else if v, ok := kv["src"]; ok {
		fl.SrcIP = v
	}
	if v, ok := kv["dstip"]; ok {
		fl.DstIP = v
	} else if v, ok := kv["dst"]; ok {
		fl.DstIP = v
	}
	if v, ok := kv["service"]; ok {
		fl.Service = v
	} else if v, ok := kv["dstport"]; ok {
		fl.Service = "port-" + v
	}
	if v, ok := kv["msg"]; ok {
		fl.Message = v
	}
	if v, ok := kv["logdesc"]; ok && fl.Message == "" {
		fl.Message = v
	}
	if fl.Message == "" {
		// build a message from action + service + ips
		parts := []string{}
		if fl.Action != "" {
			parts = append(parts, "action="+fl.Action)
		}
		if fl.Service != "" {
			parts = append(parts, "service="+fl.Service)
		}
		if fl.SrcIP != "" {
			parts = append(parts, fl.SrcIP)
		}
		if fl.DstIP != "" {
			parts = append(parts, "-> "+fl.DstIP)
		}
		fl.Message = strings.Join(parts, " ")
	}

	// CEF format
	if strings.HasPrefix(msg, "CEF:") {
		parts := strings.SplitN(msg, "|", 8)
		if len(parts) >= 8 {
			fl.LogType = parts[5]
			fl.Message = parts[5] + " " + parts[4]
			if fl.DeviceName == "" {
				fl.DeviceName = parts[1] + " " + parts[2]
			}
			if fl.Action == "" {
				fl.Action = parts[4]
			}
			ext := parts[7]
			for _, pair := range strings.Split(ext, " ") {
				kv2 := strings.SplitN(pair, "=", 2)
				if len(kv2) != 2 {
					continue
				}
				switch kv2[0] {
				case "src":
					fl.SrcIP = kv2[1]
				case "dst":
					fl.DstIP = kv2[1]
				case "dvc":
					fl.DeviceIP = kv2[1]
				case "dvchost":
					fl.DeviceName = kv2[1]
				case "act":
					fl.Action = kv2[1]
				case "spt", "dpt":
					fl.Service = "port-" + kv2[1]
				}
			}
		}
	}

	// Require at least one real field to avoid inserting empty rows
	if fl.DeviceName == "" && fl.Action == "" && fl.SrcIP == "" && fl.DstIP == "" && fl.Message == "" {
		return nil
	}

	// Risk classification
	ml := strings.ToLower(fl.Message + " " + fl.Action)
	riskKeywords := map[string]string{
		"attack": "high", "malware": "high", "intrusion": "high",
		"root login": "high", "admin password changed": "critical",
		"deny": "high", "block": "high", "vpn tunnel down": "high",
		"interface down": "high", "authentication failure": "high",
		"brute force": "high", "port scan": "medium", "dns": "low",
		"ssl": "low", "update": "low", "config change": "medium",
	}
	for kw, risk := range riskKeywords {
		if strings.Contains(ml, kw) {
			if risk == "critical" || (risk == "high" && fl.RiskLevel == "low") {
				fl.RiskLevel = risk
			} else if risk == "medium" && fl.RiskLevel == "low" {
				fl.RiskLevel = risk
			}
		}
	}

	return fl
}

func parseKV(s string) map[string]string {
	r := make(map[string]string)
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" {
			break
		}
		eq := strings.IndexByte(s, '=')
		if eq <= 0 {
			break
		}
		key := strings.TrimSpace(s[:eq])
		s = s[eq+1:]
		if len(key) == 0 {
			break
		}

		var val string
		if len(s) > 0 && s[0] == '"' {
			end := strings.IndexByte(s[1:], '"')
			if end < 0 {
				val = s[1:]
				s = ""
			} else {
				val = s[1 : end+1]
				s = s[end+2:]
			}
		} else {
			end := strings.IndexAny(s, " \t")
			if end < 0 {
				val = s
				s = ""
			} else {
				val = s[:end]
				s = s[end+1:]
			}
		}
		r[strings.ToLower(key)] = val
	}
	return r
}

// ─── HTTP HANDLERS ───────────────────────────────────────────────────────────

func jsonResp(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func jsonErr(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func handleLogin(db *DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var creds struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
			jsonErr(w, "bad request", http.StatusBadRequest)
			return
		}

		var u User
		err := db.QueryRow("SELECT id,username,password_hash,is_admin,must_reset_password FROM users WHERE username=?", creds.Username).
			Scan(&u.ID, &u.Username, &u.PasswordHash, &u.IsAdmin, &u.MustResetPassword)
		if err != nil {
			jsonErr(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(creds.Password)) != nil {
			jsonErr(w, "invalid credentials", http.StatusUnauthorized)
			return
		}

		db.Exec("UPDATE users SET last_login=datetime('now') WHERE id=?", u.ID)
		token := makeToken(u.ID, u.Username, u.IsAdmin)
		jsonResp(w, map[string]interface{}{
			"token":              token,
			"must_reset_password": u.MustResetPassword,
			"user": map[string]interface{}{
				"id":       u.ID,
				"username": u.Username,
				"is_admin": u.IsAdmin,
			},
		})
	}
}

func handleChangePassword(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Old string `json:"old_password"`
			New string `json:"new_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonErr(w, "bad request", http.StatusBadRequest)
			return
		}

		uid, _ := strconv.ParseInt(r.Header.Get("X-User-ID"), 10, 64)
		var hash string
		db.QueryRow("SELECT password_hash FROM users WHERE id=?", uid).Scan(&hash)
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Old)) != nil {
			jsonErr(w, "current password incorrect", http.StatusUnauthorized)
			return
		}

		h, _ := bcrypt.GenerateFromPassword([]byte(req.New), bcrypt.DefaultCost)
		db.Exec("UPDATE users SET password_hash=?, must_reset_password=0 WHERE id=?", string(h), uid)
		jsonResp(w, map[string]string{"ok": "password changed"})
	})
}

func handleGetMe(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := strconv.ParseInt(r.Header.Get("X-User-ID"), 10, 64)
		var u User
		err := db.QueryRow("SELECT id, username, is_admin, must_reset_password FROM users WHERE id=?", uid).
			Scan(&u.ID, &u.Username, &u.IsAdmin, &u.MustResetPassword)
		if err != nil {
			jsonErr(w, "user not found", http.StatusNotFound)
			return
		}
		jsonResp(w, map[string]interface{}{
			"id":                 u.ID,
			"username":           u.Username,
			"is_admin":           u.IsAdmin,
			"must_reset_password": u.MustResetPassword,
		})
	})
}

func handleListUsers(db *DB) http.HandlerFunc {
	return adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		rows, _ := db.Query("SELECT id,username,is_admin,must_reset_password,created_at,last_login FROM users")
		defer rows.Close()
		var users []map[string]interface{}
		for rows.Next() {
			var u User
			rows.Scan(&u.ID, &u.Username, &u.IsAdmin, &u.MustResetPassword, &u.CreatedAt, &u.LastLogin)
			users = append(users, map[string]interface{}{
				"id": u.ID, "username": u.Username, "is_admin": u.IsAdmin,
				"must_reset_password": u.MustResetPassword,
				"created_at":          u.CreatedAt.Format(time.RFC3339),
			})
		}
		jsonResp(w, users)
	})
}

func handleCreateUser(db *DB) http.HandlerFunc {
	return adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
			IsAdmin  bool   `json:"is_admin"`
		}
		json.NewDecoder(r.Body).Decode(&req)
		if req.Username == "" || req.Password == "" {
			jsonErr(w, "username and password required", http.StatusBadRequest)
			return
		}
		h, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		_, err := db.Exec("INSERT INTO users (username,password_hash,is_admin,must_reset_password) VALUES (?,?,?,1)",
			req.Username, string(h), req.IsAdmin)
		if err != nil {
			jsonErr(w, "user exists", http.StatusConflict)
			return
		}
		jsonResp(w, map[string]string{"ok": "created"})
	})
}

func handleDeleteUser(db *DB) http.HandlerFunc {
	return adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/users/")
		if id == "" {
			jsonErr(w, "id required", http.StatusBadRequest)
			return
		}
		if id == r.Header.Get("X-User-ID") {
			jsonErr(w, "cannot delete self", http.StatusBadRequest)
			return
		}
		db.Exec("DELETE FROM users WHERE id=?", id)
		jsonResp(w, map[string]string{"ok": "deleted"})
	})
}

func handleResetPassword(db *DB) http.HandlerFunc {
	return adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/users/")
		id := strings.TrimSuffix(path, "/reset-password")
		h, _ := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
		db.Exec("UPDATE users SET password_hash=?, must_reset_password=1 WHERE id=?", string(h), id)
		jsonResp(w, map[string]string{"ok": "reset to 'admin'"})
	})
}

func handleGetTopTalkers(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		rng := safeTimeRange(r.URL.Query().Get("range"))
		limit := 10
		if l, _ := strconv.Atoi(r.URL.Query().Get("limit")); l > 0 {
			limit = l
		}
		q := fmt.Sprintf("SELECT src_ip, SUM(bytes) AS total FROM flow_records WHERE collected_at > datetime('now','-%s') GROUP BY src_ip ORDER BY total DESC LIMIT %d", rng, limit)
		rows, _ := db.Query(q)
		defer rows.Close()
		res := make([]map[string]interface{}, 0)
		for rows.Next() {
			var ip string
			var b uint64
			rows.Scan(&ip, &b)
			res = append(res, map[string]interface{}{"ip": ip, "bytes": b})
		}
		jsonResp(w, res)
	})
}

func handleGetTopServices(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		rng := safeTimeRange(r.URL.Query().Get("range"))
		limit := 10
		if l, _ := strconv.Atoi(r.URL.Query().Get("limit")); l > 0 {
			limit = l
		}
		q := fmt.Sprintf("SELECT dst_port, SUM(bytes) AS total FROM flow_records WHERE collected_at > datetime('now','-%s') AND dst_port > 0 GROUP BY dst_port ORDER BY total DESC LIMIT %d", rng, limit)
		rows, _ := db.Query(q)
		defer rows.Close()
		res := make([]map[string]interface{}, 0)
		for rows.Next() {
			var port uint16
			var b uint64
			rows.Scan(&port, &b)
			res = append(res, map[string]interface{}{"port": port, "service": categorizePort(port), "bytes": b})
		}
		jsonResp(w, res)
	})
}

func handleGetTrafficSummary(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		rng := safeTimeRange(r.URL.Query().Get("range"))
		var total uint64
		var cnt uint64
		db.QueryRow(fmt.Sprintf("SELECT COALESCE(SUM(bytes),0), COUNT(*) FROM flow_records WHERE collected_at > datetime('now','-%s')", rng)).Scan(&total, &cnt)
		jsonResp(w, map[string]interface{}{"total_bytes": total, "connections": cnt, "period": rng})
	})
}

func handleGetTotalTraffic(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var day, week, month uint64
		db.QueryRow(`SELECT 
			COALESCE(SUM(CASE WHEN collected_at > datetime('now','-1 day') THEN bytes ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN collected_at > datetime('now','-7 days') THEN bytes ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN collected_at > datetime('now','-30 days') THEN bytes ELSE 0 END), 0)
			FROM flow_records`).Scan(&day, &week, &month)
		jsonResp(w, map[string]uint64{"day": day, "week": week, "month": month})
	})
}

func handleGetFlowsByIP(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimPrefix(r.URL.Path, "/api/flows/by-ip/")
		rng := safeTimeRange(r.URL.Query().Get("range"))
		var total uint64
		db.QueryRow(fmt.Sprintf("SELECT COALESCE(SUM(bytes),0) FROM flow_records WHERE (src_ip=? OR dst_ip=?) AND collected_at > datetime('now','-%s')", rng), ip, ip).Scan(&total)
		jsonResp(w, map[string]interface{}{"ip": ip, "bytes": total})
	})
}

func handleGetFlowsByService(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		svc := strings.TrimPrefix(r.URL.Path, "/api/flows/by-service/")
		port, _ := strconv.Atoi(svc)
		rng := safeTimeRange(r.URL.Query().Get("range"))
		var total uint64
		db.QueryRow(fmt.Sprintf("SELECT COALESCE(SUM(bytes),0) FROM flow_records WHERE (src_port=? OR dst_port=?) AND collected_at > datetime('now','-%s')", rng), port, port).Scan(&total)
		jsonResp(w, map[string]interface{}{"service": svc, "bytes": total})
	})
}

func handleGetInterfaces(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		rows, _ := db.Query(`SELECT i.id,i.device_id,i.idx,i.name,i.descr,i.speed,i.admin_status,i.oper_status,
			i.in_octets,i.out_octets,i.in_errors,i.out_errors,i.last_updated,d.name,d.ip 
			FROM interfaces i JOIN snmp_devices d ON i.device_id=d.id ORDER BY d.name,i.idx`)
		defer rows.Close()
		res := make([]IfaceView, 0)
		for rows.Next() {
			v := IfaceView{}
			var lu sql.NullString
			rows.Scan(&v.ID, &v.DeviceID, &v.Idx, &v.Name, &v.Description, &v.Speed,
				&v.AdminStatus, &v.OperStatus, &v.InOctets, &v.OutOctets,
				&v.InErrors, &v.OutErrors, &lu, &v.DeviceName, &v.DeviceIP)
			if lu.Valid {
				v.LastUpdated = lu.String
			}
			res = append(res, v)
		}
		jsonResp(w, res)
	})
}

func handleGetDevices(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		rows, _ := db.Query("SELECT id,name,ip,snmp_version,community,security_level,snmp_username,auth_proto,auth_pass,priv_proto,priv_pass,poll_interval,enabled,last_poll FROM snmp_devices")
		defer rows.Close()
		res := make([]SNMPDevice, 0)
		for rows.Next() {
			d := SNMPDevice{}
			var lp sql.NullString
			rows.Scan(&d.ID, &d.Name, &d.IP, &d.SNMPVersion, &d.Community, &d.SecurityLevel,
				&d.SnmpUsername, &d.AuthProto, &d.AuthPass, &d.PrivProto, &d.PrivPass,
				&d.PollInterval, &d.Enabled, &lp)
			d.LastPoll = lp.String
			res = append(res, d)
		}
		jsonResp(w, res)
	})
}

func handleCreateDevice(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var d SNMPDevice
		json.NewDecoder(r.Body).Decode(&d)
		if d.PollInterval == 0 {
			d.PollInterval = 60
		}
		if d.Community == "" {
			d.Community = "public"
		}
		r2, err := db.Exec("INSERT INTO snmp_devices (name,ip,snmp_version,community,security_level,snmp_username,auth_proto,auth_pass,priv_proto,priv_pass,poll_interval,enabled) VALUES (?,?,?,?,?,?,?,?,?,?,?,1)",
			d.Name, d.IP, d.SNMPVersion, d.Community, d.SecurityLevel, d.SnmpUsername,
			d.AuthProto, d.AuthPass, d.PrivProto, d.PrivPass, d.PollInterval)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusConflict)
			return
		}
		id, _ := r2.LastInsertId()
		jsonResp(w, map[string]int64{"id": id})
	})
}

func handleUpdateDevice(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/devices/")
		var d SNMPDevice
		json.NewDecoder(r.Body).Decode(&d)
		db.Exec("UPDATE snmp_devices SET name=?,ip=?,snmp_version=?,community=?,security_level=?,snmp_username=?,auth_proto=?,auth_pass=?,priv_proto=?,priv_pass=?,poll_interval=?,enabled=? WHERE id=?",
			d.Name, d.IP, d.SNMPVersion, d.Community, d.SecurityLevel, d.SnmpUsername,
			d.AuthProto, d.AuthPass, d.PrivProto, d.PrivPass,
			d.PollInterval, d.Enabled, id)
		jsonResp(w, map[string]string{"ok": "updated"})
	})
}

func handleDeleteDevice(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/api/devices/")
		db.Exec("DELETE FROM snmp_devices WHERE id=?", id)
		jsonResp(w, map[string]string{"ok": "deleted"})
	})
}

func handleGetLogs(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		limit := 50
		offset := 0
		if l, _ := strconv.Atoi(r.URL.Query().Get("limit")); l > 0 {
			limit = l
		}
		if o, _ := strconv.Atoi(r.URL.Query().Get("offset")); o > 0 {
			offset = o
		}
		action := r.URL.Query().Get("action")
		risk := r.URL.Query().Get("risk")

		q := "SELECT id,ts,device_name,device_ip,log_type,action,message,src_ip,dst_ip,service,risk_level FROM fortigate_logs WHERE 1=1"
		var args []interface{}
		if action != "" {
			q += " AND action=?"
			args = append(args, action)
		}
		if risk != "" {
			q += " AND risk_level=?"
			args = append(args, risk)
		}
		q += " ORDER BY ts DESC LIMIT ? OFFSET ?"
		args = append(args, limit, offset)

		rows, _ := db.Query(q, args...)
		defer rows.Close()
		res := make([]FLog, 0)
		for rows.Next() {
			var l FLog
			rows.Scan(&l.ID, &l.Timestamp, &l.DeviceName, &l.DeviceIP, &l.LogType,
				&l.Action, &l.Message, &l.SrcIP, &l.DstIP, &l.Service, &l.RiskLevel)
			res = append(res, l)
		}
		jsonResp(w, res)
	})
}

func handleGetLogStats(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		rows, _ := db.Query("SELECT risk_level,COUNT(*) FROM fortigate_logs GROUP BY risk_level")
		defer rows.Close()
		res := make(map[string]int)
		for rows.Next() {
			var l string
			var c int
			rows.Scan(&l, &c)
			res[l] = c
		}
		jsonResp(w, res)
	})
}

func handleGetChangeLog(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		rows, _ := db.Query(`SELECT id,ts,device_name,device_ip,log_type,action,message,risk_level 
			FROM fortigate_logs WHERE risk_level IN ('high','critical') ORDER BY ts DESC LIMIT 100`)
		defer rows.Close()
		res := make([]map[string]interface{}, 0)
		for rows.Next() {
			var l FLog
			rows.Scan(&l.ID, &l.Timestamp, &l.DeviceName, &l.DeviceIP, &l.LogType, &l.Action, &l.Message, &l.RiskLevel)
			res = append(res, map[string]interface{}{
				"id": l.ID, "timestamp": l.Timestamp,
				"device": l.DeviceName, "action": l.Action,
				"message": l.Message, "risk": l.RiskLevel,
			})
		}
		jsonResp(w, res)
	})
}

func handleGetTiles(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := strconv.ParseInt(r.Header.Get("X-User-ID"), 10, 64)
		rows, _ := db.Query("SELECT id,user_id,tile_type,title,config,pos_x,pos_y,width,height FROM dashboard_tiles WHERE user_id=?", uid)
		defer rows.Close()
		var tiles []Tile
		for rows.Next() {
			var t Tile
			rows.Scan(&t.ID, &t.UserID, &t.Type, &t.Title, &t.Config, &t.PosX, &t.PosY, &t.Width, &t.Height)
			tiles = append(tiles, t)
		}
		if len(tiles) == 0 {
			tiles = []Tile{
				{Type: "top-talkers", Title: "Top Talkers", Width: 4, Height: 3},
				{Type: "top-services", Title: "Top Services", Width: 4, Height: 3, PosX: 4},
				{Type: "traffic-summary", Title: "Traffic Summary", Width: 8, Height: 3, PosY: 3},
				{Type: "bandwidth", Title: "Bandwidth (Day/Week/Month)", Width: 4, Height: 3, PosX: 8, PosY: 0},
				{Type: "change-log", Title: "Recent Changes", Width: 8, Height: 3, PosY: 6},
				{Type: "interface-stats", Title: "Interface Stats", Width: 4, Height: 3, PosX: 8, PosY: 3},
				{Type: "fortigate-summary", Title: "FortiGate Summary", Width: 4, Height: 3, PosX: 8, PosY: 6},
			}
		}
		jsonResp(w, tiles)
	})
}

func handleSaveTiles(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		uid, _ := strconv.ParseInt(r.Header.Get("X-User-ID"), 10, 64)
		var tiles []Tile
		json.NewDecoder(r.Body).Decode(&tiles)
		db.Exec("DELETE FROM dashboard_tiles WHERE user_id=?", uid)
		for _, t := range tiles {
			db.Exec("INSERT INTO dashboard_tiles (user_id,tile_type,title,config,pos_x,pos_y,width,height) VALUES (?,?,?,?,?,?,?,?)",
				uid, t.Type, t.Title, t.Config, t.PosX, t.PosY, t.Width, t.Height)
		}
		jsonResp(w, map[string]string{"ok": "saved"})
	})
}

func handleDashboardStats(db *DB) http.HandlerFunc {
	return authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var (
			topTalkers, topServices, logs []map[string]interface{}
			day, week, month, total       uint64
			logStats                      map[string]int
		)

		// Combined totals query - single pass
		db.QueryRow(`SELECT 
			COALESCE(SUM(CASE WHEN collected_at > datetime('now','-1 day') THEN bytes ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN collected_at > datetime('now','-7 days') THEN bytes ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN collected_at > datetime('now','-30 days') THEN bytes ELSE 0 END), 0),
			COALESCE(SUM(bytes), 0) FROM flow_records`).Scan(&day, &week, &month, &total)

		// Top talkers (1h)
		r1, _ := db.Query("SELECT src_ip,SUM(bytes) AS b FROM flow_records WHERE collected_at > datetime('now','-1h') GROUP BY src_ip ORDER BY b DESC LIMIT 10")
		if r1 != nil {
			for r1.Next() {
				var ip string; var b uint64
				r1.Scan(&ip, &b)
				topTalkers = append(topTalkers, map[string]interface{}{"ip": ip, "bytes": b})
			}
			r1.Close()
		}

		// Top services (1h)
		r2, _ := db.Query("SELECT dst_port,SUM(bytes) AS b FROM flow_records WHERE collected_at > datetime('now','-1h') AND dst_port>0 GROUP BY dst_port ORDER BY b DESC LIMIT 10")
		if r2 != nil {
			for r2.Next() {
				var p uint16; var b uint64
				r2.Scan(&p, &b)
				topServices = append(topServices, map[string]interface{}{"port": p, "service": categorizePort(p), "bytes": b})
			}
			r2.Close()
		}

		// Log stats
		r3, _ := db.Query("SELECT risk_level,COUNT(*) FROM fortigate_logs GROUP BY risk_level")
		logStats = make(map[string]int)
		if r3 != nil {
			for r3.Next() {
				var l string; var c int
				r3.Scan(&l, &c)
				logStats[l] = c
			}
			r3.Close()
		}

		// Recent changes
		r4, _ := db.Query("SELECT id,ts,device_name,action,message,risk_level FROM fortigate_logs WHERE risk_level IN ('high','critical') ORDER BY ts DESC LIMIT 20")
		if r4 != nil {
			for r4.Next() {
				var l FLog
				r4.Scan(&l.ID, &l.Timestamp, &l.DeviceName, &l.Action, &l.Message, &l.RiskLevel)
				logs = append(logs, map[string]interface{}{
					"id": l.ID, "ts": l.Timestamp, "device": l.DeviceName, "action": l.Action, "message": l.Message, "risk": l.RiskLevel,
				})
			}
			r4.Close()
		}

		jsonResp(w, map[string]interface{}{
			"top_talkers":          topTalkers,
			"top_services":         topServices,
			"top_sources":          topTalkers,
			"total_traffic":        total,
			"traffic_day":          day,
			"traffic_week":         week,
			"traffic_month":        month,
			"fortigate_log_stats":  logStats,
			"recent_changes":       logs,
		})
	})
}

// ─── ROUTER ──────────────────────────────────────────────────────────────────

func makeRouter(db *DB) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/login", handleLogin(db))
	mux.HandleFunc("/api/change-password", handleChangePassword(db))
	mux.HandleFunc("/api/me", handleGetMe(db))

	// Users (admin)
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleListUsers(db)(w, r)
		case http.MethodPost:
			handleCreateUser(db)(w, r)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
	mux.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/reset-password") {
			if r.Method == http.MethodPost {
				handleResetPassword(db)(w, r)
				return
			}
		}
		if r.Method == http.MethodDelete {
			handleDeleteUser(db)(w, r)
			return
		}
		http.Error(w, "method not allowed", 405)
	})

	// Flows
	mux.HandleFunc("/api/flows/top-talkers", handleGetTopTalkers(db))
	mux.HandleFunc("/api/flows/top-services", handleGetTopServices(db))
	mux.HandleFunc("/api/flows/summary", handleGetTrafficSummary(db))
	mux.HandleFunc("/api/flows/total-traffic", handleGetTotalTraffic(db))
	mux.HandleFunc("/api/flows/by-ip/", handleGetFlowsByIP(db))
	mux.HandleFunc("/api/flows/by-service/", handleGetFlowsByService(db))
	mux.HandleFunc("/api/flows/top-sources", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		rng := safeTimeRange(r.URL.Query().Get("range"))
		limit := 10
		if l, _ := strconv.Atoi(r.URL.Query().Get("limit")); l > 0 {
			limit = l
		}
		q := fmt.Sprintf(`SELECT src_ip, COUNT(*) as hits, SUM(bytes) as total FROM flow_records WHERE collected_at > datetime('now','-%s') GROUP BY src_ip ORDER BY hits DESC LIMIT %d`, rng, limit)
		rows, _ := db.Query(q)
		defer rows.Close()
		res := make([]map[string]interface{}, 0)
		for rows.Next() {
			var ip string
			var hits int
			var b uint64
			rows.Scan(&ip, &hits, &b)
			res = append(res, map[string]interface{}{"ip": ip, "hits": hits, "bytes": b})
		}
		jsonResp(w, res)
	}))

	// Interfaces
	mux.HandleFunc("/api/interfaces", handleGetInterfaces(db))

	// Devices
	mux.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetDevices(db)(w, r)
		case http.MethodPost:
			handleCreateDevice(db)(w, r)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
	mux.HandleFunc("/api/devices/export", adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		devices, err := getDevices(db, false)
		if err != nil {
			jsonErr(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="netflow-config.json"`)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"exported_at": time.Now().UTC().Format(time.RFC3339),
			"devices":     devices,
		})
	}))
	mux.HandleFunc("/api/devices/import", adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		var payload struct {
			Devices []SNMPDevice `json:"devices"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			jsonErr(w, "invalid json", http.StatusBadRequest)
			return
		}
		imported := 0
		for _, d := range payload.Devices {
			if d.Name == "" || d.IP == "" {
				continue
			}
			if d.PollInterval == 0 {
				d.PollInterval = 60
			}
			if d.Community == "" {
				d.Community = "public"
			}
			_, err := db.Exec(`INSERT INTO snmp_devices (name,ip,snmp_version,community,security_level,snmp_username,auth_proto,auth_pass,priv_proto,priv_pass,poll_interval,enabled)
				VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
				d.Name, d.IP, d.SNMPVersion, d.Community, d.SecurityLevel, d.SnmpUsername,
				d.AuthProto, d.AuthPass, d.PrivProto, d.PrivPass, d.PollInterval, d.Enabled)
			if err != nil {
				continue // duplicate IP or invalid - skip
			}
			imported++
		}
		jsonResp(w, map[string]int{"imported": imported})
	}))
	mux.HandleFunc("/api/devices/", func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/scan") && r.Method == http.MethodPost:
			authMiddleware(func(w http.ResponseWriter, r *http.Request) {
				idStr := strings.TrimPrefix(r.URL.Path, "/api/devices/")
				idStr = strings.TrimSuffix(idStr, "/scan")
				id, _ := strconv.ParseInt(idStr, 10, 64)
				if id == 0 {
					jsonErr(w, "invalid device id", http.StatusBadRequest)
					return
				}
				result := snmpScanWithResult(db, id)
				jsonResp(w, result)
			})(w, r)
		case r.Method == http.MethodPut:
			handleUpdateDevice(db)(w, r)
		case r.Method == http.MethodDelete:
			handleDeleteDevice(db)(w, r)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})

	// FortiGate logs
	mux.HandleFunc("/api/fortigate/logs", handleGetLogs(db))
	mux.HandleFunc("/api/fortigate/stats", handleGetLogStats(db))
	mux.HandleFunc("/api/fortigate/changelog", handleGetChangeLog(db))

	// Dashboard
	mux.HandleFunc("/api/dashboard/tiles", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetTiles(db)(w, r)
		case http.MethodPost:
			handleSaveTiles(db)(w, r)
		default:
			http.Error(w, "method not allowed", 405)
		}
	})
	mux.HandleFunc("/api/dashboard/stats", handleDashboardStats(db))
	mux.HandleFunc("/api/system/status", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		var flows, ifaces, logs, devices int
		db.QueryRow("SELECT COUNT(*) FROM flow_records").Scan(&flows)
		db.QueryRow("SELECT COUNT(*) FROM interfaces").Scan(&ifaces)
		db.QueryRow("SELECT COUNT(*) FROM fortigate_logs").Scan(&logs)
		db.QueryRow("SELECT COUNT(*) FROM snmp_devices").Scan(&devices)
		jsonResp(w, map[string]int{
			"flow_records": flows, "interfaces": ifaces,
			"fortigate_logs": logs, "snmp_devices": devices,
		})
	}))
	mux.HandleFunc("/api/system/clear", adminMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", 405)
			return
		}
		db.mu.Lock()
		db.Exec("DELETE FROM flow_records")
		db.Exec("DELETE FROM interfaces")
		db.Exec("DELETE FROM fortigate_logs")
		db.Exec("DELETE FROM dashboard_tiles")
		db.mu.Unlock()
		jsonResp(w, map[string]string{"ok": "all data cleared"})
	}))

	// Static files with SPA fallback
	fs := http.FileServer(http.Dir("public"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// API routes handled above, everything else SPA
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		// Try serving the file, fallback to index.html
		path := "public" + r.URL.Path
		if _, err := os.Stat(path); err == nil {
			fs.ServeHTTP(w, r)
		} else {
			http.ServeFile(w, r, "public/index.html")
		}
	})

	return mux
}

// ─── DEMO DATA ──────────────────────────────────────────────────────────────

func seedDemoData(db *DB) {
	var cnt int
	db.QueryRow("SELECT COUNT(*) FROM flow_records").Scan(&cnt)
	if cnt > 0 {
		return // already has data
	}

	log.Println("Seeding demo data...")
	now := time.Now().UTC()
	ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5",
		"172.16.1.1", "172.16.1.2", "192.168.1.1", "192.168.1.100", "192.168.1.200",
		"8.8.8.8", "1.1.1.1", "142.250.80.46", "151.101.1.140", "104.16.132.229"}
	ports := []uint16{80, 443, 22, 53, 3389, 8080, 8443, 3306, 5432, 25, 993, 443, 80, 443, 8080}

	tx, _ := db.Begin()
	defer tx.Rollback()
	stmt, _ := tx.Prepare("INSERT INTO flow_records (src_ip,dst_ip,src_port,dst_port,protocol,bytes,packets,first_switched,last_switched,collected_at) VALUES (?,?,?,?,?,?,?,?,?,?)")

	for i := 0; i < 500; i++ {
		src := ips[rand.Intn(len(ips))]
		dst := ips[rand.Intn(len(ips))]
		if src == dst {
			dst = ips[(rand.Intn(len(ips))+1)%len(ips)]
		}
		sport := ports[rand.Intn(len(ports))]
		dport := ports[rand.Intn(len(ports))]
		proto := uint8(6) // TCP
		if dport == 53 || sport == 53 {
			proto = 17 // UDP
		}
		bytes := uint64(rand.Intn(1000000) + 100)
		pkts := uint32(bytes/64 + 1)
		ts := now.Add(-time.Duration(rand.Intn(3600)) * time.Second)
		stmt.Exec(src, dst, sport, dport, proto, bytes, pkts, ts.Format("2006-01-02 15:04:05"), ts.Format("2006-01-02 15:04:05"), ts.Format("2006-01-02 15:04:05"))
	}
	tx.Commit()

	// Seed some demo logs
	logTypes := []string{"traffic", "event", "system", "threat", "vpn"}
	actions := []string{"allow", "deny", "drop", "close", "open"}
	risks := []string{"low", "low", "low", "medium", "high", "critical"}
	for i := 0; i < 50; i++ {
		lt := logTypes[rand.Intn(len(logTypes))]
		action := actions[rand.Intn(len(actions))]
		risk := risks[rand.Intn(len(risks))]
		ts := now.Add(-time.Duration(rand.Intn(3600)) * time.Second)
		db.Exec(`INSERT INTO fortigate_logs (ts,device_name,device_ip,log_type,action,message,src_ip,dst_ip,service,risk_level,raw_log)
			VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			ts.Format("2006-01-02 15:04:05"), "FG-100E", "192.168.1.1", lt, action,
			fmt.Sprintf("Demo %s event from %s %s", lt, ips[rand.Intn(len(ips))], ips[rand.Intn(len(ips))]),
			ips[rand.Intn(len(ips))], ips[rand.Intn(len(ips))], fmt.Sprintf("Port-%d", ports[rand.Intn(len(ports))]),
			risk, "demo log entry")
	}

	log.Printf("Seeded %d flow records and %d fortigate logs", 500, 50)
}

func cleanupBadData(db *DB) {
	// Data version marker - old flow records were written by a broken
	// fixed-offset parser and are garbage. Wipe once, then keep.
	var ver string
	db.QueryRow("SELECT value FROM meta WHERE key='data_version'").Scan(&ver)
	if ver != "2" {
		if res, err := db.Exec("DELETE FROM flow_records"); err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				log.Printf("Wiped %d flow records (old parser format)", n)
			}
		}
		db.Exec("INSERT OR REPLACE INTO meta (key,value) VALUES ('data_version','2')")
	}
	// Remove flow records with no usable IPs
	if res, err := db.Exec("DELETE FROM flow_records WHERE src_ip='' OR src_ip='0.0.0.0' OR dst_ip='' OR dst_ip='0.0.0.0'"); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("Cleaned %d invalid flow records", n)
		}
	}
	// Remove log rows with no extracted fields
	if res, err := db.Exec(`DELETE FROM fortigate_logs WHERE device_name='' AND action='' AND src_ip='' AND dst_ip='' AND message=''`); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("Cleaned %d empty fortigate log rows", n)
		}
	}
}

// ─── MAIN ────────────────────────────────────────────────────────────────────
func main() {
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "netflow.db"
	}

	db, err := openDB(dbPath)
	if err != nil {
		log.Fatalf("DB: %v", err)
	}
	defer db.Close()

	// Start collectors
	go startNetflow(db, 2055)
	time.Sleep(100 * time.Millisecond)
	go startSNMPPoller(db)
	time.Sleep(100 * time.Millisecond)
	go startSyslog(db, 514)

	// Seed demo data if explicitly enabled
	if os.Getenv("DEMO_DATA") == "true" || os.Getenv("DEMO_DATA") == "1" {
		seedDemoData(db)
	}

	// Remove garbage rows from old broken parsers
	cleanupBadData(db)

	// Start API
	router := makeRouter(db)
	server := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Println("API on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP: %v", err)
		}
	}()

	// Wait for signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down...")
}
