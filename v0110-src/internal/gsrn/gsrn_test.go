package gsrn

import (
        "bytes"
        "encoding/hex"
        "testing"
)

// TestListenPacketMatchesCapture verifies that NewListen with the right
// inputs produces the exact 128-byte _gs_listen packet that gs-netcat
// v1.4.42 sent on the wire during A5.
//
// Captured packet (analysis §12.2):
//
//      01 01 03 00 00 00 00 00 00 00 00 00 00 00 00 00
//      70 b5 30 23 15 6f 3b b7 a7 a0 72 09 af 85 f2 36
//      07 c7 cd fa ad 58 8b 99 9a 7e 1b c9 87 3b c5 b8
//      00 00 ... (80 bytes of zeros) ...
//
// Inputs:
//   - secret = "MyTestSecret123" → addr = 07c7cdfaad588b999a7e1bc9873bc5b8
//   - token  = 70b53023156f3bb7a7a07209af85f236 (random, this is what was captured)
//   - flags  = 0x00 (LISTEN does NOT set FAST_CONNECT)
func TestListenPacketMatchesCapture(t *testing.T) {
        addr, _ := hex.DecodeString("07c7cdfaad588b999a7e1bc9873bc5b8")
        var token [16]byte
        tb, _ := hex.DecodeString("70b53023156f3bb7a7a07209af85f236")
        copy(token[:], tb)

        p, err := NewListen(addr, token, 0x00)
        if err != nil {
                t.Fatalf("NewListen: %v", err)
        }

        // Build the expected 128-byte packet.
        want := make([]byte, 128)
        want[0] = 0x01 // type=LISTEN
        want[1] = 0x01 // version_major
        want[2] = 0x03 // version_minor (v1.3)
        want[3] = 0x00 // flags
        copy(want[16:32], token[:])
        copy(want[32:48], addr)

        if !bytes.Equal(p[:], want) {
                t.Fatalf("LISTEN packet mismatch:\n got %s\nwant %s",
                        hex.EncodeToString(p[:]), hex.EncodeToString(want))
        }
}

// TestConnectPacketMatchesCapture verifies that NewConnect produces the
// exact 128-byte _gs_connect packet A5 captured from real gs-netcat.
//
// Captured packet (analysis §12.2):
//
//      02 01 03 04 00 00 00 00 00 00 00 00 00 00 00 00
//      00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
//      07 c7 cd fa ad 58 8b 99 9a 7e 1b c9 87 3b c5 b8
//      00 00 ... (80 bytes of zeros) ...
//
// Inputs:
//   - addr  = 07c7cdfaad588b999a7e1bc9873bc5b8 (same as listen)
//   - flags = 0x04 (FAST_CONNECT — default since v1.4.31)
//   - token = all zeros (NOTUSED in CONNECT per the C struct)
func TestConnectPacketMatchesCapture(t *testing.T) {
        addr, _ := hex.DecodeString("07c7cdfaad588b999a7e1bc9873bc5b8")

        p, err := NewConnect(addr, FlagFastConnect)
        if err != nil {
                t.Fatalf("NewConnect: %v", err)
        }

        want := make([]byte, 128)
        want[0] = 0x02 // type=CONNECT
        want[1] = 0x01 // version_major
        want[2] = 0x03 // version_minor
        want[3] = 0x04 // flags=FAST_CONNECT
        copy(want[32:48], addr)

        if !bytes.Equal(p[:], want) {
                t.Fatalf("CONNECT packet mismatch:\n got %s\nwant %s",
                        hex.EncodeToString(p[:]), hex.EncodeToString(want))
        }
}

// TestControlPacketSizes verifies that all control packets are exactly
// 32 bytes (the protocol's fixed control-packet size).
func TestControlPacketSizes(t *testing.T) {
        if len(NewPing()[:]) != 32 {
                t.Fatalf("PING packet is %d bytes, want 32", len(NewPing()[:]))
        }
        if len(NewPong()[:]) != 32 {
                t.Fatalf("PONG packet is %d bytes, want 32", len(NewPong()[:]))
        }
        if len(NewAccept()[:]) != 32 {
                t.Fatalf("ACCEPT packet is %d bytes, want 32", len(NewAccept()[:]))
        }
        if len(NewStart(StartServer)[:]) != 32 {
                t.Fatalf("START packet is %d bytes, want 32", len(NewStart(StartServer)[:]))
        }
        if len(NewStatus(StatusFatal, StatusConnRefused, "no listener")[:]) != 32 {
                t.Fatalf("STATUS packet is %d bytes, want 32",
                        len(NewStatus(StatusFatal, StatusConnRefused, "no listener")[:]))
        }
}

// TestStartPacketRoleBits exercises _gs_start parsing.
func TestStartPacketRoleBits(t *testing.T) {
        srv := NewStart(StartServer)
        if !srv.IsStartServer() || srv.IsStartClient() {
                t.Fatalf("START server parse failed: flags=0x%02x", srv.StartFlags())
        }
        cli := NewStart(StartClient)
        if !cli.IsStartClient() || cli.IsStartServer() {
                t.Fatalf("START client parse failed: flags=0x%02x", cli.StartFlags())
        }
        both := NewStart(StartServer | StartClient)
        if !both.IsStartServer() || !both.IsStartClient() {
                t.Fatalf("START both parse failed: flags=0x%02x", both.StartFlags())
        }
}

// TestStatusErrorFormatting exercises StatusError.Error() for the codes
// gs-netcat is most likely to see.
func TestStatusErrorFormatting(t *testing.T) {
        cases := []struct {
                err  StatusError
                want string
        }{
                {StatusError{StatusFatal, StatusConnRefused, ""}, "gsrn: status FATAL CONNREFUSED"},
                {StatusError{StatusFatal, StatusBadAuth, "wrong token"}, "gsrn: status FATAL BAD_AUTH: wrong token"},
                {StatusError{StatusWarn, StatusServerOK, ""}, "gsrn: status WARN SERVER_OK"},
        }
        for _, c := range cases {
                got := c.err.Error()
                if got != c.want {
                        t.Fatalf("StatusError.Error():\n got %q\nwant %q", got, c.want)
                }
        }
}

// TestStatusMsgParsing verifies that StatusMsg trims trailing NULs and
// returns the embedded ASCII string.
func TestStatusMsgParsing(t *testing.T) {
        p := NewStatus(StatusFatal, StatusConnRefused, "no listener at this addr")
        got := p.StatusMsg()
        want := "no listener at this addr"
        if got != want {
                t.Fatalf("StatusMsg: got %q, want %q", got, want)
        }

        // Overlong message is truncated to 28 bytes.
        long := NewStatus(StatusFatal, StatusProtoError,
                "this message is way too long and should be truncated to 28 bytes")
        if len(long.StatusMsg()) > 28 {
                t.Fatalf("StatusMsg not truncated: %q (len %d)",
                        long.StatusMsg(), len(long.StatusMsg()))
        }

        // Empty message.
        empty := NewStatus(StatusWarn, StatusServerOK, "")
        if empty.StatusMsg() != "" {
                t.Fatalf("StatusMsg should be empty, got %q", empty.StatusMsg())
        }
}

// TestFlagValuesMatchCHeader verifies that the protocol flag constants
// match gsocket.h:GS_FL_PROTO_* exactly (wire compatibility).
//
//      GS_FL_PROTO_WAIT              0x01   (-w)
//      GS_FL_PROTO_CLIENT_OR_SERVER  0x02   (-A)
//      GS_FL_PROTO_FAST_CONNECT      0x04   (default in CONNECT)
//      GS_FL_PROTO_LOW_LATENCY       0x08   (-k)
//      GS_FL_PROTO_SERVER_CHECK      0x10   (--check)
func TestFlagValuesMatchCHeader(t *testing.T) {
        cases := []struct {
                name string
                got  byte
                want byte
        }{
                {"FlagWait", FlagWait, 0x01},
                {"FlagClientOrServer", FlagClientOrServer, 0x02},
                {"FlagFastConnect", FlagFastConnect, 0x04},
                {"FlagLowLatency", FlagLowLatency, 0x08},
                {"FlagServerCheck", FlagServerCheck, 0x10},
        }
        for _, c := range cases {
                if c.got != c.want {
                        t.Errorf("%s = 0x%02x, want 0x%02x (C: gsocket.h)", c.name, c.got, c.want)
                }
        }
}

// TestDialFastConnectAutoClear verifies that Dial() applies the same
// FAST_CONNECT auto-clear logic as gsocket-engine.c lines 1885/1888:
// when WAIT or CLIENT_OR_SERVER is in opts.Flags, FAST_CONNECT must be
// stripped from the wire packet even though Dial would normally OR it in.
//
// We can't call Dial without a live relay, so we extract the logic into
// resolveConnectFlags (below) and test it directly. This is the exact
// same function Dial calls.
func TestDialFastConnectAutoClear(t *testing.T) {
        cases := []struct {
                name  string
                in    byte
                want  byte
        }{
                {"default (empty)", 0x00, 0x04},                      // FAST_CONNECT added
                {"LOW_LATENCY alone", FlagLowLatency, 0x0c},          // 0x04 | 0x08
                {"SERVER_CHECK alone", FlagServerCheck, 0x14},        // 0x04 | 0x10
                {"WAIT clears FAST_CONNECT", FlagWait, 0x01},         // FAST_CONNECT stripped
                {"CLIENT_OR_SERVER clears FAST_CONNECT", FlagClientOrServer, 0x02},
                {"WAIT+CLIENT_OR_SERVER clears FAST_CONNECT", FlagWait | FlagClientOrServer, 0x03},
                {"LOW_LATENCY+WAIT: FAST_CONNECT stripped, LOW_LATENCY kept",
                        FlagLowLatency | FlagWait, 0x09}, // 0x01 | 0x08
        }
        for _, c := range cases {
                got := resolveConnectFlags(c.in)
                if got != c.want {
                        t.Errorf("%s: resolveConnectFlags(0x%02x) = 0x%02x, want 0x%02x",
                                c.name, c.in, got, c.want)
                }
        }
}

// resolveConnectFlags is defined in gsrn.go (not in this _test.go file)
// so Dial() can call it. We import nothing extra here; the function is
// in the same package.

// TestStartPacketWireLayout verifies the exact byte layout of a _gs_start
// packet against the C struct _gs_start from gsocket.h:
//
//      struct _gs_start { uint8_t type; uint8_t flags; uint8_t reserved[30]; };
//
// We check the full 32 bytes: type at [0], flags at [1], rest zero.
func TestStartPacketWireLayout(t *testing.T) {
        p := NewStart(StartServer)
        if p[0] != TypeStart {
                t.Errorf("START type byte: got 0x%02x, want 0x%02x", p[0], TypeStart)
        }
        if p[1] != StartServer {
                t.Errorf("START flags byte: got 0x%02x, want 0x%02x", p[1], StartServer)
        }
        for i := 2; i < 32; i++ {
                if p[i] != 0 {
                        t.Errorf("START reserved byte [%d]: got 0x%02x, want 0x00", i, p[i])
                }
        }
}

// TestStatusPacketWireLayout verifies _gs_status byte layout against the
// C struct _gs_status:
//
//      struct _gs_status { uint8_t type; uint8_t err_type; uint8_t code;
//                          uint8_t reserved; uint8_t msg[28]; };
func TestStatusPacketWireLayout(t *testing.T) {
        p := NewStatus(StatusFatal, StatusConnRefused, "no listener")
        if p[0] != TypeStatus {
                t.Errorf("STATUS type: got 0x%02x, want 0x%02x", p[0], TypeStatus)
        }
        if p[1] != StatusFatal {
                t.Errorf("STATUS err_type: got 0x%02x, want 0x%02x", p[1], StatusFatal)
        }
        if p[2] != StatusConnRefused {
                t.Errorf("STATUS code: got 0x%02x, want 0x%02x", p[2], StatusConnRefused)
        }
        if p[3] != 0 {
                t.Errorf("STATUS reserved[3]: got 0x%02x, want 0x00", p[3])
        }
        // msg field is NUL-padded.
        if p[4] != 'n' || p[5] != 'o' {
                t.Errorf("STATUS msg start: got %q, want 'no'", string(p[4:6]))
        }
        // After the message, rest should be NUL.
        end := 4 + len("no listener")
        for i := end; i < 32; i++ {
                if p[i] != 0 {
                        t.Errorf("STATUS msg padding [%d]: got 0x%02x, want 0x00", i, p[i])
                }
        }
}

// TestAcceptPacketWireLayout verifies _gs_accept is 32 bytes with type=0x06
// and all other bytes zero (matching struct _gs_accept).
func TestAcceptPacketWireLayout(t *testing.T) {
        p := NewAccept()
        if p[0] != TypeAccept {
                t.Errorf("ACCEPT type: got 0x%02x, want 0x%02x", p[0], TypeAccept)
        }
        for i := 1; i < 32; i++ {
                if p[i] != 0 {
                        t.Errorf("ACCEPT byte [%d]: got 0x%02x, want 0x00", i, p[i])
                }
        }
}
