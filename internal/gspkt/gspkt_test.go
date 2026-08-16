package gspkt

import (
	"bytes"
	"errors"
	"testing"
)

// --- MsgSize parity with lib/packet.c ---------------------------------------

func TestMsgSize(t *testing.T) {
	cases := []struct {
		typ  int
		want int
	}{
		{0, -2}, // FATAL
		{1, 4},  // WSIZE
		{2, 4},  // IDS
		{3, 4},  // PWD
		{15, 4},
		{16, 16}, // PING/PONG
		{31, 16},
		{32, 64}, // LOG
		{33, 64}, // STATUS
		{47, 64},
		{48, 128},
		{63, 128},
		{64, 512},
		{79, 512},
		{80, 1024},
		{95, 1024},
		{96, 2048},
		{111, 2048},
		{112, 4196}, // sic! matches C original
		{127, 4196},
	}
	for _, c := range cases {
		got := MsgSize(c.typ)
		if got != c.want {
			t.Errorf("MsgSize(%d) = %d, want %d", c.typ, got, c.want)
		}
	}
}

// --- Encode/decode data: ESC doubling round-trip ----------------------------

func TestEncodeDataAlloc_RoundTrip(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{0x00},
		{0xFB},       // single ESC → ESC ESC
		{0xFB, 0xFB}, // ESC ESC → ESC ESC ESC ESC
		{1, 2, 3, 4, 5},
		{0xFB, 1, 0xFB, 2, 0xFB},
		bytes.Repeat([]byte{0xFB}, 100),
	}
	for i, in := range cases {
		enc := EncodeDataAlloc(in)
		dec := NewDecoder()
		out := make([]byte, 4*len(enc)+16)
		var events []Event
		c, w, err := dec.Decode(enc, out, &events)
		if err != nil {
			t.Fatalf("case %d: Decode err: %v", i, err)
		}
		if c != len(enc) {
			t.Errorf("case %d: consumed %d, want %d", i, c, len(enc))
		}
		if !bytes.Equal(out[:w], in) {
			t.Errorf("case %d: round-trip mismatch\n  in : %x\n  out: %x", i, in, out[:w])
		}
		if len(events) != 0 {
			t.Errorf("case %d: expected 0 events, got %d", i, len(events))
		}
	}
}

// --- Msg encode/decode ------------------------------------------------------

func TestEncodeMsg_BadType(t *testing.T) {
	if _, err := EncodeMsg(0, nil); !errors.Is(err, ErrProtocol) {
		t.Errorf("EncodeMsg(0,nil) err = %v, want ErrProtocol", err)
	}
	if _, err := EncodeMsg(1, []byte{1, 2, 3}); err == nil {
		t.Errorf("EncodeMsg(1,[3 bytes]) should fail (want 4-byte payload)")
	}
	if _, err := EncodeMsg(1, []byte{1, 2, 3, 4, 5}); err == nil {
		t.Errorf("EncodeMsg(1,[5 bytes]) should fail")
	}
}

func TestEncodeDecodeMsg_WSIZE(t *testing.T) {
	// WSIZE: type=1, payload=4 bytes
	payload := []byte{0x00, 0x50, 0x00, 0x18} // 80 cols, 24 rows
	wire, err := EncodeMsg(MsgWSIZE, payload)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xFB, 0x01, 0x00, 0x50, 0x00, 0x18}
	if !bytes.Equal(wire, want) {
		t.Errorf("WSIZE wire = %x, want %x", wire, want)
	}

	dec := NewDecoder()
	out := make([]byte, 64)
	var events []Event
	_, w, err := dec.Decode(wire, out, &events)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Kind != EventMessage || e.Type != MsgWSIZE {
		t.Errorf("event kind/type = %v/%d, want Msg/%d", e.Kind, e.Type, MsgWSIZE)
	}
	if !bytes.Equal(e.Data, payload) {
		t.Errorf("event data = %x, want %x", e.Data, payload)
	}
	if w != 0 {
		t.Errorf("data bytes = %x, want none", out[:w])
	}
}

func TestEncodeDecodeMsg_PING(t *testing.T) {
	// PING: type=16, 16-byte payload (struct _pkt_app_ping: flags + reserved[3] + user[12])
	payload := make([]byte, 16)
	payload[0] = 0x01
	copy(payload[4:], []byte("hello-ping!")) // 11 bytes; last byte stays 0

	wire, err := EncodeMsg(MsgPING, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != MsgHdrLen+16 {
		t.Errorf("PING wire len = %d, want %d", len(wire), MsgHdrLen+16)
	}

	dec := NewDecoder()
	out := make([]byte, 64)
	var events []Event
	if _, _, err := dec.Decode(wire, out, &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Kind != EventMessage || e.Type != MsgPING {
		t.Errorf("event kind/type = %v/%d, want Msg/%d", e.Kind, e.Type, MsgPING)
	}
	if !bytes.Equal(e.Data, payload) {
		t.Errorf("PING data = %x, want %x", e.Data, payload)
	}
}

func TestEncodeDecodeMsg_LOG(t *testing.T) {
	// LOG: type=32, 64-byte payload (type byte + 63-byte msg)
	payload := make([]byte, 64)
	payload[0] = 3 // GS_PKT_APP_LOG_TYPE_INFO
	copy(payload[1:], []byte("hello from log"))

	wire, err := EncodeMsg(MsgLOG, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != MsgHdrLen+64 {
		t.Errorf("LOG wire len = %d, want %d", len(wire), MsgHdrLen+64)
	}

	dec := NewDecoder()
	out := make([]byte, 128)
	var events []Event
	if _, _, err := dec.Decode(wire, out, &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if !bytes.Equal(events[0].Data, payload) {
		t.Errorf("LOG data mismatch")
	}
}

// --- Chn encode/decode ------------------------------------------------------

func TestEncodeChn_BadType(t *testing.T) {
	if _, err := EncodeChn(MaxChn, nil); err == nil {
		t.Errorf("EncodeChn(MaxChn,nil) should fail")
	}
	long := make([]byte, 0x10000)
	if _, err := EncodeChn(0, long); err == nil {
		t.Errorf("EncodeChn(0, 64KiB) should fail")
	}
}

func TestEncodeDecodeChn_PWD(t *testing.T) {
	// PWD channel: chn=8, payload=NUL-terminated string
	payload := []byte("/home/user\x00")
	wire, err := EncodeChn(ChnPWD, payload)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xFB, MaxMsg + ChnPWD, 0x00, byte(len(payload))}
	want = append(want, payload...)
	if !bytes.Equal(wire, want) {
		t.Errorf("PWD wire = %x, want %x", wire, want)
	}

	dec := NewDecoder()
	out := make([]byte, 64)
	var events []Event
	if _, _, err := dec.Decode(wire, out, &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	e := events[0]
	if e.Kind != EventChannel || e.Type != ChnPWD {
		t.Errorf("event kind/type = %v/%d, want Chn/%d", e.Kind, e.Type, ChnPWD)
	}
	if !bytes.Equal(e.Data, payload) {
		t.Errorf("PWD data = %x, want %x", e.Data, payload)
	}
}

func TestEncodeDecodeChn_ZeroLen(t *testing.T) {
	// Zero-length channel packet: must still emit an event.
	wire, err := EncodeChn(ChnDATA, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xFB, MaxMsg + ChnDATA, 0x00, 0x00}
	if !bytes.Equal(wire, want) {
		t.Errorf("zero-len chn wire = %x, want %x", wire, want)
	}

	dec := NewDecoder()
	out := make([]byte, 64)
	var events []Event
	if _, _, err := dec.Decode(wire, out, &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(events))
	}
	if events[0].Type != ChnDATA || len(events[0].Data) != 0 {
		t.Errorf("event wrong: %+v", events[0])
	}
}

// --- Mixed data + in-band events -------------------------------------------

func TestDecode_MixedDataAndPings(t *testing.T) {
	// Stream: "abc" + ESC ESC (literal 0xFB) + PING + "def"
	pingPayload := make([]byte, 16)
	pingPayload[0] = 0x01
	pingWire, _ := EncodeMsg(MsgPING, pingPayload)

	stream := []byte("abc")
	stream = append(stream, ESC, ESC) // literal 0xFB
	stream = append(stream, pingWire...)
	stream = append(stream, []byte("def")...)

	dec := NewDecoder()
	out := make([]byte, 256)
	var events []Event
	c, w, err := dec.Decode(stream, out, &events)
	if err != nil {
		t.Fatalf("Decode err: %v", err)
	}
	if c != len(stream) {
		t.Errorf("consumed = %d, want %d", c, len(stream))
	}
	wantData := []byte{'a', 'b', 'c', 0xFB, 'd', 'e', 'f'}
	if !bytes.Equal(out[:w], wantData) {
		t.Errorf("data = %x, want %x", out[:w], wantData)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %d: %+v", len(events), events)
	}
	if events[0].Type != MsgPING {
		t.Errorf("event type = %d, want %d", events[0].Type, MsgPING)
	}
	if !bytes.Equal(events[0].Data, pingPayload) {
		t.Errorf("PING data mismatch")
	}
}

// --- Partial packets: split across calls -----------------------------------

func TestDecode_PartialMsgAcrossCalls(t *testing.T) {
	// WSIZE: type=1, 4 bytes payload, split into 3 chunks
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	wire, _ := EncodeMsg(MsgWSIZE, payload)

	dec := NewDecoder()
	out := make([]byte, 64)
	var events []Event

	// Chunk 1: ESC only
	c1, w1, err := dec.Decode(wire[:1], out, &events)
	if err != nil || c1 != 1 || w1 != 0 || len(events) != 0 {
		t.Fatalf("chunk1: c=%d w=%d err=%v events=%d", c1, w1, err, len(events))
	}
	// Chunk 2: type byte + 2 payload bytes
	c2, w2, err := dec.Decode(wire[1:4], out, &events)
	if err != nil || c2 != 3 || w2 != 0 || len(events) != 0 {
		t.Fatalf("chunk2: c=%d w=%d err=%v events=%d", c2, w2, err, len(events))
	}
	// Chunk 3: remaining 2 payload bytes
	c3, w3, err := dec.Decode(wire[4:], out, &events)
	if err != nil || c3 != 2 || w3 != 0 || len(events) != 1 {
		t.Fatalf("chunk3: c=%d w=%d err=%v events=%d", c3, w3, err, len(events))
	}
	if !bytes.Equal(events[0].Data, payload) {
		t.Errorf("data = %x, want %x", events[0].Data, payload)
	}
}

func TestDecode_PartialChnAcrossCalls(t *testing.T) {
	payload := []byte("/var/log\x00")
	wire, _ := EncodeChn(ChnPWD, payload)

	dec := NewDecoder()
	out := make([]byte, 64)
	var events []Event

	// Split: [ESC, type, len_hi], [len_lo, payload[0..3]], [payload[4..]]
	c1, _, err := dec.Decode(wire[:3], out, &events)
	if err != nil || c1 != 3 || len(events) != 0 {
		t.Fatalf("chunk1: c=%d err=%v events=%d", c1, err, len(events))
	}
	c2, _, err := dec.Decode(wire[3:8], out, &events)
	if err != nil || c2 != 5 || len(events) != 0 {
		t.Fatalf("chunk2: c=%d err=%v events=%d", c2, err, len(events))
	}
	c3, _, err := dec.Decode(wire[8:], out, &events)
	if err != nil || c3 != len(wire)-8 || len(events) != 1 {
		t.Fatalf("chunk3: c=%d err=%v events=%d", c3, err, len(events))
	}
	if !bytes.Equal(events[0].Data, payload) {
		t.Errorf("data = %x, want %x", events[0].Data, payload)
	}
}

// --- Protocol error: type 0 ------------------------------------------------

func TestDecode_ProtocolErrorTypeZero(t *testing.T) {
	stream := []byte{ESC, 0x00}
	dec := NewDecoder()
	out := make([]byte, 8)
	var events []Event
	_, _, err := dec.Decode(stream, out, &events)
	if !errors.Is(err, ErrProtocol) {
		t.Errorf("err = %v, want ErrProtocol", err)
	}
}

// --- Multiple events in one stream -----------------------------------------

func TestDecode_MultipleEventsOneStream(t *testing.T) {
	p1 := []byte{0, 80, 0, 24} // WSIZE
	p2 := make([]byte, 16)     // PING
	p2[0] = 1
	p3 := []byte("/tmp\x00") // PWD chn

	w1, _ := EncodeMsg(MsgWSIZE, p1)
	w2, _ := EncodeMsg(MsgPING, p2)
	w3, _ := EncodeChn(ChnPWD, p3)

	stream := append([]byte("pre-"), w1...)
	stream = append(stream, w2...)
	stream = append(stream, w3...)
	stream = append(stream, []byte("-post")...)

	dec := NewDecoder()
	out := make([]byte, 256)
	var events []Event
	c, w, err := dec.Decode(stream, out, &events)
	if err != nil {
		t.Fatal(err)
	}
	if c != len(stream) {
		t.Errorf("consumed = %d, want %d", c, len(stream))
	}
	wantData := []byte("pre--post")
	if !bytes.Equal(out[:w], wantData) {
		t.Errorf("data = %q, want %q", out[:w], wantData)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 events, got %d", len(events))
	}
	if events[0].Type != MsgWSIZE || !bytes.Equal(events[0].Data, p1) {
		t.Errorf("event[0] wrong: %+v", events[0])
	}
	if events[1].Type != MsgPING || !bytes.Equal(events[1].Data, p2) {
		t.Errorf("event[1] wrong: %+v", events[1])
	}
	if events[2].Kind != EventChannel || events[2].Type != ChnPWD || !bytes.Equal(events[2].Data, p3) {
		t.Errorf("event[2] wrong: %+v", events[2])
	}
}

// --- Decoder reuse: multiple Decode calls on a continuous stream -----------

func TestDecoder_ContinuousStream(t *testing.T) {
	dec := NewDecoder()
	out := make([]byte, 256)
	var allEvents []Event
	var allData []byte

	chunks := [][]byte{
		[]byte("hello "),
		EncodeDataAlloc([]byte{0xFB, 0xFB}),
		(func() []byte {
			b, _ := EncodeMsg(MsgWSIZE, []byte{0, 80, 0, 24})
			return b
		})(),
		[]byte(" world"),
	}
	for _, ch := range chunks {
		var events []Event
		_, w, err := dec.Decode(ch, out, &events)
		if err != nil {
			t.Fatal(err)
		}
		allData = append(allData, out[:w]...)
		allEvents = append(allEvents, events...)
	}
	wantData := []byte{'h', 'e', 'l', 'l', 'o', ' ', 0xFB, 0xFB, ' ', 'w', 'o', 'r', 'l', 'd'}
	if !bytes.Equal(allData, wantData) {
		t.Errorf("data = %x, want %x", allData, wantData)
	}
	if len(allEvents) != 1 || allEvents[0].Type != MsgWSIZE {
		t.Errorf("events wrong: %+v", allEvents)
	}
}

// --- Parity with C: explicit hand-crafted wire from pkt_app_send_* ---------
//
// Mirrors pkt_app_send_ping in tools/pkt_mgr.c:
//
//	p->wbuf[0] = GS_PKT_ESC;       // 0xFB
//	p->wbuf[1] = PKT_MSG_PING;     // 16
//	p->wlen = 2 + GS_PKT_MSG_size_by_type(PKT_MSG_PING);  // 2 + 16 = 18
//	payload is struct _pkt_app_ping (16 bytes, all zero by default).
func TestParity_PingWireFromC(t *testing.T) {
	want := make([]byte, 18)
	want[0] = 0xFB
	want[1] = 16

	payload := make([]byte, 16)
	got, err := EncodeMsg(MsgPING, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("C-parity ping wire = %x, want %x", got, want)
	}
}

// Parity with pkt_app_send_pwdreply (channel PWD):
//
//	hdr->esc = 0xFB
//	hdr->type = GS_PKT_CHN2TYPE(GS_CHN_PWD) = 128 + 8 = 136 (0x88)
//	hdr->len = htons(strlen(wd)+1)
//	payload = wd + '\0'
func TestParity_PwdReplyWireFromC(t *testing.T) {
	wd := "/home/foo"
	payload := append([]byte(wd), 0)
	got, err := EncodeChn(ChnPWD, payload)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xFB, 0x88, 0x00, byte(len(payload))}
	want = append(want, payload...)
	if !bytes.Equal(got, want) {
		t.Errorf("C-parity pwd wire = %x, want %x", got, want)
	}
}
