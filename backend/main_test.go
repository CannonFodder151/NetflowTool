package main

import (
	"encoding/binary"
	"testing"
	"time"
)

// ─── SNMP value conversion ───────────────────────────────────────────────────

func TestToStr(t *testing.T) {
	cases := []struct {
		in   interface{}
		want string
	}{
		{[]byte("port1"), "port1"},
		{"port2", "port2"},
		{nil, ""},
	}
	for _, c := range cases {
		if got := toStr(c.in); got != c.want {
			t.Errorf("toStr(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestToUint64(t *testing.T) {
	cases := []struct {
		in   interface{}
		want uint64
		ok   bool
	}{
		{uint(1000), 1000, true},
		{uint32(1000), 1000, true},
		{uint64(1000), 1000, true},
		{int(1000), 1000, true},
		{int32(1000), 1000, true},
		{int64(1000), 1000, true},
		{[]byte{0, 0, 3, 232}, 1000, true},          // 4-byte big endian
		{[]byte{0, 0, 0, 0, 0, 0, 3, 232}, 1000, true}, // 8-byte big endian
		{nil, 0, false},
	}
	for _, c := range cases {
		got, ok := toUint64(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("toUint64(%v) = %d,%v want %d,%v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// ─── NetFlow v9 parser ───────────────────────────────────────────────────────

func buildV9Template() []byte {
	// Header: version(2) count(2) sysuptime(4) unixsecs(4) seq(4) sourceid(4)
	var pkt []byte
	head := make([]byte, 20)
	binary.BigEndian.PutUint16(head[0:2], 9)  // version
	binary.BigEndian.PutUint16(head[2:4], 1)  // count = 1 flowset
	binary.BigEndian.PutUint32(head[4:8], 0)  // sysUpTime
	binary.BigEndian.PutUint32(head[8:12], 1700000000) // unixSecs
	binary.BigEndian.PutUint32(head[12:16], 0) // seq
	binary.BigEndian.PutUint32(head[16:20], 1) // sourceID
	pkt = append(pkt, head...)

	// Template FlowSet: id=0, length, template record
	// fields: 8(IPV4_SRC_ADDR,4) 12(IPV4_DST_ADDR,4) 7(L4_SRC_PORT,2) 11(L4_DST_PORT,2) 4(PROTOCOL,1) 1(IN_BYTES,4) 2(IN_PKTS,4) 10(INPUT_SNMP,4) 14(OUTPUT_SNMP,4)
	fieldCount := 9
	tplLen := 4 + fieldCount*4 // templateID(2)+fieldCount(2)+fields
	fsLen := 4 + tplLen
	tplFs := make([]byte, fsLen)
	binary.BigEndian.PutUint16(tplFs[0:2], 0)      // setID = template
	binary.BigEndian.PutUint16(tplFs[2:4], uint16(fsLen))
	binary.BigEndian.PutUint16(tplFs[4:6], 256)    // templateID 256
	binary.BigEndian.PutUint16(tplFs[6:8], uint16(fieldCount))
	fields := [][2]uint16{
		{8, 4}, {12, 4}, {7, 2}, {11, 2}, {4, 1}, {1, 4}, {2, 4}, {10, 4}, {14, 4},
	}
	for i, f := range fields {
		off := 8 + i*4
		binary.BigEndian.PutUint16(tplFs[off:off+2], f[0])
		binary.BigEndian.PutUint16(tplFs[off+2:off+4], f[1])
	}
	pkt = append(pkt, tplFs...)
	return pkt
}

func buildV9Data() []byte {
	var pkt []byte
	head := make([]byte, 20)
	binary.BigEndian.PutUint16(head[0:2], 9)
	binary.BigEndian.PutUint16(head[2:4], 1)
	binary.BigEndian.PutUint32(head[8:12], 1700000000)
	binary.BigEndian.PutUint32(head[16:20], 1)
	pkt = append(pkt, head...)

	// Data FlowSet: id=256, one record of 25 bytes
	recLen := 4 + 4 + 2 + 2 + 1 + 4 + 4 + 4 + 4 // 29 bytes
	fsLen := 4 + recLen
	fs := make([]byte, fsLen)
	binary.BigEndian.PutUint16(fs[0:2], 256)
	binary.BigEndian.PutUint16(fs[2:4], uint16(fsLen))
	rec := fs[4:]
	rec[0], rec[1], rec[2], rec[3] = 10, 0, 0, 1    // src 10.0.0.1
	rec[4], rec[5], rec[6], rec[7] = 8, 8, 8, 8     // dst 8.8.8.8
	binary.BigEndian.PutUint16(rec[8:10], 12345)    // src port
	binary.BigEndian.PutUint16(rec[10:12], 443)     // dst port
	rec[12] = 6                                      // tcp
	binary.BigEndian.PutUint32(rec[13:17], 100000)  // bytes
	binary.BigEndian.PutUint32(rec[17:21], 200)     // packets
	binary.BigEndian.PutUint32(rec[21:25], 1)       // input iface
	binary.BigEndian.PutUint32(rec[25:29], 2)       // output iface
	pkt = append(pkt, fs...)
	return pkt
}

func TestParseV9TemplateAndData(t *testing.T) {
	// fresh template cache
	templateCache.Lock()
	templateCache.m = make(map[string]*nfTemplate)
	templateCache.Unlock()

	parseV9(buildV9Template(), nil, "10.0.0.1")
	parseV9(buildV9Data(), nil, "10.0.0.1")

	tpl := getTemplate("10.0.0.1", 1, 256)
	if tpl == nil {
		t.Fatal("template 256 not cached")
	}
	if len(tpl.fields) != 9 {
		t.Fatalf("expected 9 fields, got %d", len(tpl.fields))
	}
}

func TestParseDataFlow(t *testing.T) {
	templateCache.Lock()
	templateCache.m = make(map[string]*nfTemplate)
	templateCache.Unlock()
	parseV9(buildV9Template(), nil, "10.0.0.1")

	tpl := getTemplate("10.0.0.1", 1, 256)
	if tpl == nil {
		t.Fatal("template not cached")
	}
	// build data flowset body (without set header)
	fsData := buildV9Data()
	// header is 20 bytes, then set: id(2) len(2) then records
	setBody := fsData[24:]
	flows := parseDataFlow(setBody, tpl, time.Now())
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	f := flows[0]
	if f.SrcIP != "10.0.0.1" || f.DstIP != "8.8.8.8" {
		t.Errorf("bad ips: %s -> %s", f.SrcIP, f.DstIP)
	}
	if f.SrcPort != 12345 || f.DstPort != 443 {
		t.Errorf("bad ports: %d -> %d", f.SrcPort, f.DstPort)
	}
	if f.Protocol != 6 {
		t.Errorf("bad proto: %d", f.Protocol)
	}
	if f.Bytes != 100000 || f.Packets != 200 {
		t.Errorf("bad counters: %d bytes, %d pkts", f.Bytes, f.Packets)
	}
}

// ─── Syslog parser ───────────────────────────────────────────────────────────

func TestParseFLogKV(t *testing.T) {
	msg := `<189>date=2026-07-31 time=18:54:43 devname=FGT60E devid=FGT60EFG1000000001 logid=0100032001 type=traffic subtype=forward level=notice vd=root srcip=10.0.0.1 srcport=12345 srcintf="port1" dstip=8.8.8.8 dstport=443 dstintf="wan1" sessionid=100 policyid=1 proto=6 action=accept service=HTTPS msg="HTTP session accepted"`

	fl := parseFLog(msg)
	if fl == nil {
		t.Fatal("parseFLog returned nil")
	}
	if fl.DeviceName != "FGT60E" {
		t.Errorf("devname = %q", fl.DeviceName)
	}
	if fl.SrcIP != "10.0.0.1" || fl.DstIP != "8.8.8.8" {
		t.Errorf("ips: %s -> %s", fl.SrcIP, fl.DstIP)
	}
	if fl.Action != "accept" {
		t.Errorf("action = %q", fl.Action)
	}
	if fl.Service != "HTTPS" {
		t.Errorf("service = %q", fl.Service)
	}
	if fl.LogType != "traffic" {
		t.Errorf("type = %q", fl.LogType)
	}
	if fl.Timestamp != "2026-07-31 18:54:43" {
		t.Errorf("timestamp = %q", fl.Timestamp)
	}
}

func TestParseFLogCEF(t *testing.T) {
	msg := `CEF:0|Fortinet|FortiGate|7.0.0|0100032001|Traffic|3|src=10.0.0.1 dst=8.8.8.8 act=accept dvc=192.168.1.1`
	fl := parseFLog(msg)
	if fl == nil {
		t.Fatal("parseFLog returned nil")
	}
	if fl.SrcIP != "10.0.0.1" || fl.DstIP != "8.8.8.8" {
		t.Errorf("ips: %s -> %s", fl.SrcIP, fl.DstIP)
	}
	if fl.Action != "accept" {
		t.Errorf("action = %q", fl.Action)
	}
	if fl.DeviceIP != "192.168.1.1" {
		t.Errorf("dvc = %q", fl.DeviceIP)
	}
}

func TestParseFLogRejectsGarbage(t *testing.T) {
	if fl := parseFLog("random syslog line not fortigate"); fl != nil {
		t.Error("expected nil for non-FortiGate message")
	}
}
