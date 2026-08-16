// Package gsrn implements the GSRN (Global Socket Relay Network) wire
// protocol used by gs-netcat / gsocket to match two peers by a shared
// 128-bit GS-Address through a relay.
//
// Wire format summary (see /home/z/my-project/research/gs-netcat-analysis.md §6):
//
//      _gs_listen   128B  type=0x01  LC→relay  (LC = Listener)
//      _gs_connect  128B  type=0x02  CC→relay  (CC = Connector)
//      _gs_ping      32B  type=0x03  either→relay
//      _gs_pong      32B  type=0x04  relay→either
//      _gs_start     32B  type=0x05  relay→peer (assigns SSL role)
//      _gs_accept    32B  type=0x06  peer→relay
//      _gs_status    32B  type=0x07  relay→peer (error / informational)
//
// All multi-byte fields are absent (everything is byte-aligned).  Two
// packet sizes exist: 128 bytes for the initial listen/connect (carries
// GS-Address + token + flags), 32 bytes for everything else.
//
// Protocol version is hardcoded at v1.3 (maj=1, min=3) — verified on the
// wire by A5 (see analysis §12.2).
//
// The GSRN protocol is plaintext TCP — encryption happens in the TLS-SRP
// layer that runs *inside* the relayed connection.
package gsrn

import (
        "encoding/binary"
        "errors"
        "fmt"
        "io"
        "net"
        "time"
)

// Packet type bytes (offset 0 of every packet).
const (
        TypeListen  byte = 0x01
        TypeConnect byte = 0x02
        TypePing    byte = 0x03
        TypePong    byte = 0x04
        TypeStart   byte = 0x05
        TypeAccept  byte = 0x06
        TypeStatus  byte = 0x07
)

// Protocol version (gsocket.h:GS_PROTO_VERSION_MAJOR/MINOR).
const (
        VersionMajor byte = 1
        VersionMinor byte = 3 // v1.3
)

// Flag bits in the 4th byte of _gs_listen / _gs_connect.
// Values must match gsocket.h:GS_FL_PROTO_* exactly (wire-compat).
const (
        // FlagWait (0x01) — _gs_connect should block at the relay until a
        // listener appears. -w CLI flag. Mutually exclusive with FAST_CONNECT.
        FlagWait byte = 0x01

        // FlagClientOrServer (0x02) — either side may become the SSL server.
        // -A CLI flag. Default (off): first peer to register becomes the
        // listener (= SSL server). Mutually exclusive with FAST_CONNECT.
        FlagClientOrServer byte = 0x02

        // FlagFastConnect (0x04) — sent on the wire by default in CONNECT
        // packets (since gsocket v1.4.31). Per the C header comment this is
        // *meant* to tell the relay "I'll start TLS immediately, don't wait
        // for _gs_start", but the C engine itself never reads the flag
        // locally — it ALWAYS waits for _gs_start. The Go port reproduces
        // this exactly: we set the bit on the wire for relay-side
        // optimization, but our local handshake always waits for _gs_start.
        //
        // FAST_CONNECT is auto-cleared if WAIT or CLIENT_OR_SERVER is set
        // (they're documented as incompatible in gsocket.h).
        FlagFastConnect byte = 0x04

        // FlagLowLatency (0x08) — hint to the relay that this is an
        // interactive shell session (low latency preferred). -k CLI flag.
        // Compatible with FAST_CONNECT.
        FlagLowLatency byte = 0x08

        // FlagServerCheck (0x10) — ask the relay whether a listener exists
        // for this GS-Address without actually connecting. --check CLI flag.
        FlagServerCheck byte = 0x10
)

// Start-flag bits in the 2nd byte of _gs_start.
const (
        // StartServer (0x01) — set when the receiving peer should be the SSL server.
        StartServer byte = 0x01
        // StartClient (0x02) — set when the receiving peer should be the SSL client.
        StartClient byte = 0x02
)

// Status error_type field (2nd byte of _gs_status).
const (
        StatusWarn  byte = 0x01
        StatusFatal byte = 0x02
)

// Status code field (3rd byte of _gs_status).
const (
        StatusBadAuth      byte = 0x01
        StatusConnRefused  byte = 0x02
        StatusIdleTimeout  byte = 0x03
        StatusConnDenied   byte = 0x04
        StatusProtoError   byte = 0x05
        StatusServerOK     byte = 0x06
        StatusNetError     byte = 0x07
        StatusNeedUpdate   byte = 0x2A
)

// Packet sizes (fixed by the protocol).
const (
        SizeListenConnect = 128
        SizeControl       = 32
)

// DefaultPort is the default GSRN relay port (gsocket.h:GSRN_DEFAULT_PORT).
// The alternative port 7351 is used when 443 is blocked.
const DefaultPort = 443

// AltPort is the alternate relay port (used by gsocket.org when 443 is blocked).
const AltPort = 7351

// DefaultPingInterval is the relay keepalive interval (gsocket.h).
// Without periodic traffic most consumer NATs will kill the TCP connection
// after ~60 seconds.
const DefaultPingInterval = 45 * time.Second

// ListenConnect is the 128-byte _gs_listen / _gs_connect packet body.
//
// C source (gsocket.h):
//
//      struct _gs_listen  { uint8_t type; uint8_t version_major; uint8_t version_minor;
//                           uint8_t flags; uint8_t reserved1[4]; uint8_t reserved2[8];
//                           uint8_t token[16]; uint8_t addr[16];
//                           uint8_t reserved3[16]; uint8_t reserved4[64]; };
//      struct _gs_connect { uint8_t type; uint8_t version_major; uint8_t version_minor;
//                           uint8_t flags; uint8_t reserved1[4]; uint8_t reserved2[8];
//                           uint8_t token_NOTUSED[16]; uint8_t addr[16];
//                           uint8_t reserved3[16]; uint8_t reserved4[64]; };
//
// Both packets have the same wire layout — they differ only in `type`.
// For _gs_connect the token field is "NOTUSED" (always zero on the wire).
type ListenConnect [SizeListenConnect]byte

// NewListen returns a _gs_listen packet (type=0x01).
//
// Per A5 wire capture (analysis §12.2), LISTEN packets carry:
//   - type=0x01, version 1.3, flags=0x00 (LISTEN does NOT set FAST_CONNECT)
//   - random 16-byte auth-token (when GS_set_token(gs, NULL, 0) is used, the default)
//   - 16-byte GS-Address (the routing key the relay will use)
func NewListen(addr []byte, token [16]byte, flags byte) (*ListenConnect, error) {
        if len(addr) != 16 {
                return nil, fmt.Errorf("gsrn: addr must be 16 bytes, got %d", len(addr))
        }
        var p ListenConnect
        p[0] = TypeListen
        p[1] = VersionMajor
        p[2] = VersionMinor
        p[3] = flags // typically 0x00 for LISTEN
        copy(p[16:32], token[:])
        copy(p[32:48], addr)
        // remaining bytes already zero
        return &p, nil
}

// NewConnect returns a _gs_connect packet (type=0x02).
//
// Per A5 wire capture, CONNECT packets carry:
//   - type=0x02, version 1.3, flags=0x04 (FAST_CONNECT is default since v1.4.31)
//   - token field is all-zero (NOTUSED)
//   - 16-byte GS-Address
func NewConnect(addr []byte, flags byte) (*ListenConnect, error) {
        if len(addr) != 16 {
                return nil, fmt.Errorf("gsrn: addr must be 16 bytes, got %d", len(addr))
        }
        var p ListenConnect
        p[0] = TypeConnect
        p[1] = VersionMajor
        p[2] = VersionMinor
        p[3] = flags // typically 0x04 (FAST_CONNECT)
        // token field (offset 16..31) is NOTUSED and stays zero
        copy(p[32:48], addr)
        return &p, nil
}

// Type returns the packet type byte at offset 0.
func (p *ListenConnect) Type() byte { return p[0] }

// Flags returns the flag byte at offset 3.
func (p *ListenConnect) Flags() byte { return p[3] }

// Token returns the 16-byte auth-token at offset 16..31.
// For _gs_connect this field is NOTUSED and reads as zero.
func (p *ListenConnect) Token() [16]byte {
        var t [16]byte
        copy(t[:], p[16:32])
        return t
}

// Addr returns the 16-byte GS-Address at offset 32..47.
func (p *ListenConnect) Addr() [16]byte {
        var a [16]byte
        copy(a[:], p[32:48])
        return a
}

// Control is a 32-byte control packet (PING/PONG/START/ACCEPT/STATUS).
//
// All control packets share the same wire size (32B).  Layout differs by
// type — see accessors below.
type Control [SizeControl]byte

// NewPing returns a _gs_ping packet (type=0x03).  The 28-byte payload is
// zeroed, matching the C struct.
func NewPing() *Control {
        var p Control
        p[0] = TypePing
        return &p
}

// NewPong returns a _gs_pong packet (type=0x04).  The 28-byte payload is
// zeroed, matching the C struct.
func NewPong() *Control {
        var p Control
        p[0] = TypePong
        return &p
}

// NewAccept returns a _gs_accept packet (type=0x06).
// Sent by both peers to the relay after they receive _gs_start, signalling
// "understood, ready for tunnelled bytes".
func NewAccept() *Control {
        var p Control
        p[0] = TypeAccept
        return &p
}

// NewStart returns a _gs_start packet (type=0x05) with the given role flag
// (StartServer or StartClient).  Used by tests / fake relays; the real
// relay always sends this, never the peer.
func NewStart(roleFlag byte) *Control {
        var p Control
        p[0] = TypeStart
        p[1] = roleFlag
        return &p
}

// NewStatus returns a _gs_status packet (type=0x07) with err_type, code,
// and an ASCII message padded to 28 bytes.
func NewStatus(errType, code byte, msg string) *Control {
        var p Control
        p[0] = TypeStatus
        p[1] = errType
        p[2] = code
        m := []byte(msg)
        if len(m) > 28 {
                m = m[:28]
        }
        copy(p[4:32], m)
        return &p
}

// Type returns the packet type byte at offset 0.
func (p *Control) Type() byte { return p[0] }

// StartFlags returns the role flags at offset 1 of a _gs_start packet.
// Caller is responsible for ensuring this is a _gs_start.
func (p *Control) StartFlags() byte { return p[1] }

// IsStartServer returns true if the _gs_start packet tells the receiver
// to be the SSL server.
func (p *Control) IsStartServer() bool { return p[1]&StartServer != 0 }

// IsStartClient returns true if the _gs_start packet tells the receiver
// to be the SSL client.
func (p *Control) IsStartClient() bool { return p[1]&StartClient != 0 }

// StatusErrType returns the error_type byte of a _gs_status packet.
func (p *Control) StatusErrType() byte { return p[1] }

// StatusCode returns the status code byte of a _gs_status packet.
func (p *Control) StatusCode() byte { return p[2] }

// StatusMsg returns the message bytes of a _gs_status packet (offset 4..31,
// NUL-trimmed).
//
// The production GSRN relay (C-based) sometimes fills the msg field with
// non-text data (binary hash, token, or random padding) when there is no
// human-readable message to send — e.g. for CONNREFUSED it just signals
// "no listener at this GS-Address" with no extra context. In that case the
// bytes are not a valid UTF-8 string and printing them raw produces
// terminal garbage (mojibake). We detect this and return an empty string
// so the caller's error formatter omits the trailing ": <garbage>".
//
// Heuristic: if more than 25% of the non-NUL bytes are non-printable
// (control chars except common whitespace), treat the field as binary.
func (p *Control) StatusMsg() string {
        b := p[4:32]
        // Find length up to first NUL.
        n := len(b)
        for i, c := range b {
                if c == 0 {
                        n = i
                        break
                }
        }
        if n == 0 {
                return ""
        }
        msg := b[:n]
        // Count printable bytes. Printable = [0x20..0x7E] plus \t \n \r.
        printable := 0
        for _, c := range msg {
                if (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r' {
                        printable++
                }
        }
        // If more than 25% non-printable, treat as binary garbage.
        if printable*4 < n*3 {
                return ""
        }
        return string(msg)
}

// Role is the SSL role assigned to the local peer by the relay's _gs_start.
type Role int

const (
        RoleUnassigned Role = iota
        RoleServer          // we are the SSL server (LC in the default flow)
        RoleClient          // we are the SSL client (CC in the default flow)
)

// Conn wraps a TCP connection to the GSRN relay.
//
// The wrapper handles:
//   - Initial _gs_listen / _gs_connect handshake
//   - Reading _gs_start (which tells us our SSL role)
//   - Sending _gs_accept back to the relay
//   - Reading _gs_status (error/informational) at any time
//   - Periodic _gs_ping keepalive (optional; see SetPingInterval)
//
// Once Start() returns, the underlying TCP is ready to be passed to
// tlssrp.Client or tlssrp.Server — the relay will tunnel TLS-SRP bytes
// transparently between the two matched peers.
type Conn struct {
        net.Conn
        role Role
        addr [16]byte
}

// Options controls optional behaviour of a GSRN connection.
type Options struct {
        // RelayHost:Port is the relay endpoint.  Defaults to the gsocket.org
        // production relay if empty.  The hostname is hashed from the GS-Address
        // (sum(addr[0..15]) % 26 → [a-z].gs.thc.org).  We do NOT do that here;
        // callers pick a relay explicitly.
        RelayHost string
        RelayPort int

        // Flags is the bitset written to the 4th byte of _gs_listen/_gs_connect.
        // Default: 0x00 for listen, 0x04 (FAST_CONNECT) for connect.
        Flags byte

        // Token is the 16-byte auth-token sent in _gs_listen.  For _gs_connect
        // the token field is NOTUSED (always zero).  Use GenRandomToken for the
        // default behaviour, or DeriveAuthToken for the `-a` flag behaviour.
        Token [16]byte

        // PingInterval controls the keepalive ping cadence.  Zero disables
        // pinging (caller takes responsibility for keepalive).
        PingInterval time.Duration
}

// DefaultOptions returns sensible defaults for connecting to a relay.
// The Flags field here is the BASE flags before FAST_CONNECT is OR'd
// in for CONNECT packets (which happens automatically inside Dial).
// Pass FlagWait / FlagClientOrServer / FlagLowLatency here as needed.
func DefaultOptions(host string, port int) *Options {
        return &Options{
                RelayHost:    host,
                RelayPort:    port,
                Flags:        0, // FAST_CONNECT is added by Dial for CONNECT
                PingInterval: DefaultPingInterval,
        }
}

// resolveConnectFlags is the auto-clear logic Dial uses for CONNECT
// packets. It mirrors gsocket-engine.c lines 1880–1890 exactly:
//
//      FAST_CONNECT is OR'd in by default, then cleared if WAIT,
//      CLIENT_OR_SERVER, or SERVER_CHECK is set.
//
// SERVER_CHECK (0x10) is a query mode: the relay short-circuits and
// replies with _gs_status (SERVER_OK / CONNREFUSED) without putting
// the peers in contact. FAST_CONNECT is semantically incompatible
// with SERVER_CHECK because FAST_CONNECT means "connect fast, fail
// if no listener" — but SERVER_CHECK isn't trying to connect at all.
//
// Without this auto-clear, the wire packet carried flags=0x14
// (SERVER_CHECK | FAST_CONNECT). Some relays (notably c.gs.thc.org)
// interpret FAST_CONNECT first, try to find a listener, fail, and
// close the TCP connection without sending _gs_status → the caller
// sees EOF instead of a proper CONNREFUSED. This was the root cause
// of --monitor reporting "NET-ERROR" for every secret even when the
// relay was reachable.
//
// Exposed as a free function so it can be tested directly without a
// live relay (see TestDialFastConnectAutoClear).
func resolveConnectFlags(base byte) byte {
        f := base | FlagFastConnect
        if f&FlagWait != 0 || f&FlagClientOrServer != 0 || f&FlagServerCheck != 0 {
                f &^= FlagFastConnect
        }
        return f
}

// Dial connects to the relay (TCP), writes the _gs_listen or _gs_connect
// packet, and returns a *Conn ready for Start()/Accept() + TLS.
//
// `listen` true  → send _gs_listen
// `listen` false → send _gs_connect
//
// Note: Dial does NOT wait for _gs_start.  Call Start() to block for the
// role assignment.
func Dial(addr [16]byte, listen bool, opts *Options) (*Conn, error) {
        if opts == nil {
                return nil, errors.New("gsrn: nil Options")
        }
        if opts.RelayHost == "" {
                return nil, errors.New("gsrn: RelayHost is required")
        }
        if opts.RelayPort == 0 {
                opts.RelayPort = DefaultPort
        }

        tcpConn, err := net.DialTimeout("tcp",
                net.JoinHostPort(opts.RelayHost, fmt.Sprintf("%d", opts.RelayPort)),
                15*time.Second)
        if err != nil {
                return nil, fmt.Errorf("gsrn: dial relay: %w", err)
        }

        // Build the initial packet.
        var pkt *ListenConnect
        if listen {
                pkt, err = NewListen(addr[:], opts.Token, opts.Flags)
        } else {
                // CONNECT default: set FAST_CONNECT unless the caller asked for
                // WAIT or CLIENT_OR_SERVER (the two flags documented as
                // incompatible with FAST_CONNECT in gsocket.h). This mirrors
                // GS_CTX_setsockopt() in gsocket-engine.c lines 1885/1888
                // which clears FAST_CONNECT when those options are set.
                //
                // The auto-clear logic is in resolveConnectFlags (also tested
                // directly — see TestDialFastConnectAutoClear).
                pkt, err = NewConnect(addr[:], resolveConnectFlags(opts.Flags))
        }
        if err != nil {
                tcpConn.Close()
                return nil, err
        }

        // Send it (full 128 bytes).
        if _, err := tcpConn.Write(pkt[:]); err != nil {
                tcpConn.Close()
                return nil, fmt.Errorf("gsrn: write listen/connect: %w", err)
        }

        return &Conn{Conn: tcpConn, addr: addr}, nil
}

// Start blocks until the relay sends _gs_start (or _gs_status, which is
// returned as an error).  Returns the assigned SSL Role.
//
// Internally, this reads a single 32-byte control packet from the relay.
// The relay is expected to send either:
//   - _gs_start (type=0x05)  → role assignment, normal case
//   - _gs_status (type=0x07) → error (e.g. CONNREFUSED, BAD_AUTH)
//
// We do NOT consume the subsequent _gs_accept we send back; the caller
// is expected to call SendAccept() after Start() returns.
func (c *Conn) Start() (Role, error) {
        var p Control
        if _, err := io.ReadFull(c.Conn, p[:]); err != nil {
                return RoleUnassigned, fmt.Errorf("gsrn: read start/status: %w", err)
        }

        switch p.Type() {
        case TypeStart:
                // Determine role from flags.
                switch {
                case p.IsStartServer():
                        c.role = RoleServer
                case p.IsStartClient():
                        c.role = RoleClient
                default:
                        return RoleUnassigned, fmt.Errorf(
                                "gsrn: _gs_start has no role flag (flags=0x%02x)", p.StartFlags())
                }
                return c.role, nil

        case TypeStatus:
                // Convert the status code to a Go error.
                return RoleUnassigned, StatusError{
                        ErrType: p.StatusErrType(),
                        Code:    p.StatusCode(),
                        Msg:     p.StatusMsg(),
                }

        default:
                return RoleUnassigned, fmt.Errorf(
                        "gsrn: unexpected packet type 0x%02x (want _gs_start or _gs_status)",
                        p.Type())
        }
}

// SendAccept writes a _gs_accept packet (32 bytes) to the relay.
// Per the state machine (analysis §6.3), both peers send _gs_accept after
// receiving _gs_start, before the TLS handshake begins.
func (c *Conn) SendAccept() error {
        p := NewAccept()
        if _, err := c.Conn.Write(p[:]); err != nil {
                return fmt.Errorf("gsrn: write accept: %w", err)
        }
        return nil
}

// Role returns the SSL role assigned by the relay's _gs_start.
// Returns RoleUnassigned if Start() has not been called or did not yet
// complete.
func (c *Conn) Role() Role { return c.role }

// Addr returns the GS-Address this connection is for.
func (c *Conn) Addr() [16]byte { return c.addr }

// ReadPing reads a single _gs_ping from the relay and responds with a
// _gs_pong.  Returns the (parsed) ping for inspection.
//
// Callers using keepalive should run this in a goroutine that selects on
// a done channel; if the relay sends anything other than a ping, the
// function returns an error (caller should hand the bytes back to the
// main reader or close the connection).
func (c *Conn) ReadPing() error {
        var p Control
        if _, err := io.ReadFull(c.Conn, p[:]); err != nil {
                return fmt.Errorf("gsrn: read ping: %w", err)
        }
        if p.Type() != TypePing {
                return fmt.Errorf("gsrn: expected _gs_ping, got type 0x%02x", p.Type())
        }
        pong := NewPong()
        if _, err := c.Conn.Write(pong[:]); err != nil {
                return fmt.Errorf("gsrn: write pong: %w", err)
        }
        return nil
}

// SendPing writes a single _gs_ping packet (caller-driven keepalive).
func (c *Conn) SendPing() error {
        p := NewPing()
        if _, err := c.Conn.Write(p[:]); err != nil {
                return fmt.Errorf("gsrn: write ping: %w", err)
        }
        return nil
}

// StatusError is returned by Start() when the relay sends _gs_status
// instead of _gs_start.
type StatusError struct {
        ErrType byte
        Code    byte
        Msg     string
}

func (e StatusError) Error() string {
        var typ string
        switch e.ErrType {
        case StatusWarn:
                typ = "WARN"
        case StatusFatal:
                typ = "FATAL"
        default:
                typ = fmt.Sprintf("type=0x%02x", e.ErrType)
        }
        var code string
        switch e.Code {
        case StatusBadAuth:
                code = "BAD_AUTH"
        case StatusConnRefused:
                code = "CONNREFUSED"
        case StatusIdleTimeout:
                code = "IDLE_TIMEOUT"
        case StatusConnDenied:
                code = "CONNDENIED"
        case StatusProtoError:
                code = "PROTOERROR"
        case StatusServerOK:
                code = "SERVER_OK"
        case StatusNetError:
                code = "NETERROR"
        case StatusNeedUpdate:
                code = "NEEDUPDATE"
        default:
                code = fmt.Sprintf("code=0x%02x", e.Code)
        }
        if e.Msg == "" {
                return fmt.Sprintf("gsrn: status %s %s", typ, code)
        }
        return fmt.Sprintf("gsrn: status %s %s: %s", typ, code, e.Msg)
}

// IsFatal returns true if the status is a FATAL error (connection should
// be torn down).
func (e StatusError) IsFatal() bool { return e.ErrType == StatusFatal }

// silence unused-import warnings for binary (we use it for future
// extensibility — currently no multi-byte fields).
var _ = binary.BigEndian
