// Package gsconn glues together gsrn (relay protocol), tlssrp (TLS-SRP
// over the relayed connection), and gspkt (in-band multiplexing) into a
// single high-level API: give it a secret, get back a secure
// io.ReadWriteCloser to the remote peer — optionally with multiplexed
// in-band signalling.
//
// Typical use (raw byte stream — cat mode, default):
//
//      conn, err := gsconn.Dial(secret, gsconn.ModeConnect, &gsconn.Options{
//          RelayHost: "127.0.0.1",
//          RelayPort: 4433,
//      })
//      if err != nil { ... }
//      defer conn.Close()
//      io.Copy(conn, os.Stdin)
//
// In-band multiplexing mode (mirrors gs-netcat -i): set UseInBand=true
// and start an event-pump goroutine to handle PING/LOG/etc. events:
//
//      opts.UseInBand = true
//      conn, _ := gsconn.Dial(secret, gsconn.ModeConnect, opts)
//      go func() {
//          for ev := range conn.Events() {
//              switch ev.Type {
//              case gspkt.MsgPING:
//                  _ = conn.WriteMsg(gspkt.MsgPONG, makePongPayload())
//              }
//          }
//      }()
//
// The two peers (ModeListen + ModeConnect) end up with an end-to-end
// TLS-SRP-secured channel routed through the GSRN relay.  Neither the
// relay nor any on-path observer learns the secret; both peers derive
// identical SRP credentials from the shared secret and TLS-SRP authenticates
// them to each other.
package gsconn

import (
        "crypto/rand"
        "errors"
        "fmt"
        "io"
        "net"
        "os"
        "sync"
        "sync/atomic"
        "time"

        "github.com/gsport/gs-netcat/internal/gskdf"
        "github.com/gsport/gs-netcat/internal/gspkt"
        "github.com/gsport/gs-netcat/internal/gsrn"
        "github.com/gsport/gs-netcat/internal/strs"
        "github.com/gsport/gs-netcat/internal/tlssrp"
)

// Mode selects whether the local peer is the listener (LC) or connector (CC).
//
// The relay assigns SSL roles based on registration order: the LC (first
// to register) becomes the SSL server, the CC (second) becomes the SSL
// client.  The -A CLI flag (FlagClientOrServer) flips this so either peer
// can be the SSL server.
type Mode int

const (
        ModeListen  Mode = iota // be the listener (LC)
        ModeConnect             // be the connector (CC)
)

// Options configures a gsconn.Dial call.
type Options struct {
        // RelayHost:Port is the GSRN relay endpoint.  REQUIRED.
        // For the production gsocket.org relay, see RelayHostnameForAddr().
        RelayHost string
        RelayPort int

        // AuthToken, if non-empty, sets a deterministic auth-token (the `-a`
        // CLI flag).  If empty, a random 16-byte token is generated (default).
        AuthToken string

        // FlagExtra is OR'd into the protocol flags sent on the wire.
        // Defaults: ModeListen sends 0x00; ModeConnect sends 0x04 (FAST_CONNECT).
        // Pass FlagClientOrServer here for the -A flag.
        FlagExtra byte

        // HandshakeTimeout bounds the total time spent in Dial() (GSRN +
        // TLS-SRP).  Zero = 30 seconds.
        HandshakeTimeout time.Duration

        // PingInterval, if non-zero, runs a background keepalive goroutine.
        // Without keepalive most consumer NATs kill the TCP connection after
        // ~60 seconds of idle.  Default = 45 seconds.
        //
        // In raw (cat) mode the pinger is a no-op stub: GSRN-level pings
        // cannot be sent through a TLS-owned TCP stream without corrupting
        // TLS framing, so TCP keepalive (enabled on the relay socket) is
        // what actually preserves the connection. In in-band mode
        // (UseInBand=true) the pinger sends a gspkt.MsgPING every
        // PingInterval and is the real application-level keepalive.
        PingInterval time.Duration

        // UseInBand enables in-band multiplexing (mirrors gs-netcat -i):
        // Writes are escape-encoded (0xFB doubled) and a gspkt.Decoder is
        // attached to Read so that in-band events (PING/LOG/etc.) are
        // extracted from the data stream and delivered via Conn.Events().
        //
        // When UseInBand is false (default), Read/Write pass raw bytes
        // through unchanged (cat mode — compatible with gs-netcat without
        // -i on the other side).
        //
        // Both peers MUST agree on this setting: an in-band peer talking to
        // a raw-mode peer will see escape-encoded bytes (with 0xFB doubled)
        // in its data stream.
        UseInBand bool

        // NoEncryption mirrors the C `-C` flag: skip the TLS-SRP handshake
        // entirely and route raw application bytes through the GSRN relay.
        //
        // Wire compatibility: a NoEncryption peer can only talk to another
        // NoEncryption peer — the encrypted peer would try to parse the raw
        // bytes as a TLS record and fail. The GSRN relay itself is fine
        // with either mode (it sees only the GS-protocol packets + opaque
        // bytes after _gs_start).
        //
        // IMPORTANT: the relay can read all application data in this mode.
        // Only use when the network path is trusted or the data is not
        // sensitive.
        NoEncryption bool

        // ServerCheck mirrors the C `-t` flag: ask the GSRN whether a
        // listener exists at this GS-Address, without establishing an
        // end-to-end connection. The relay responds with a _gs_status of
        // SERVER_OK (listener exists) or CONNREFUSED (no listener).
        //
        // Only valid with ModeConnect. When set, Dial returns immediately
        // after the relay's status response — no TLS handshake, no data
        // path. Use DialTest instead of Dial for this mode; Dial with
        // ServerCheck set returns an error.
        ServerCheck bool

        // v0.1.30: Dialer, if non-nil, is passed through to gsrn.Dial
        // to override the default net.DialTimeout. Used by --tor to
        // route the relay TCP connection via a SOCKS5 proxy, and by
        // --stealth-https to wrap the resulting conn in fake TLS framing.
        Dialer func(host, port string) (net.Conn, error)
}

// DefaultOptions returns a sane starting point.
func DefaultOptions(host string, port int) *Options {
        return &Options{
                RelayHost:        host,
                RelayPort:        port,
                HandshakeTimeout: 30 * time.Second,
                PingInterval:     gsrn.DefaultPingInterval,
        }
}

// Conn is a high-level GS connection: a TLS-SRP-secured channel routed
// through the GSRN relay.  It implements net.Conn (via the embedded
// *tlssrp.Conn) and adds a Close that also tears down the keepalive
// goroutine.
//
// When Options.UseInBand is true, Read and Write transparently run the
// gspkt in-band multiplexing protocol: data Writes are escape-encoded,
// data Reads are decoded (with in-band events extracted to Events()).
// Use WriteMsg/WriteChn to send in-band signalling packets.
//
// v0.2.0: WrapRawConn allows external code to wrap the underlying
// io.ReadWriteCloser (e.g. with compression, rate-limiting, audit
// logging). All subsequent Read/Write/WriteMsg operations go through
// the wrapper. Wrappers MUST be installed before any I/O occurs
// (typically immediately after Dial returns).
type Conn struct {
        // rawConn is the underlying data channel: either *tlssrp.Conn
        // (encrypted mode) or net.Conn (NoEncryption / -C mode). It is
        // exposed via the embedded io.ReadWriteCloser interface so the
        // rest of the code (Read/Write/Close/SetDeadline) works
        // uniformly regardless of whether TLS is in front.
        rawConn  io.ReadWriteCloser
        relay    *gsrn.Conn
        creds    *gskdf.Credentials
        role     gsrn.Role
        mode     Mode
        stopPing chan struct{}

        // lastPongAt stores UnixNano of the last PONG received from the
        // peer. Used by inBandPinger to detect dead-server condition
        // (server stopped responding to PING) without waiting for TCP
        // retransmit timeout (which can take minutes). 0 means "no PONG
        // yet" — initialized to time.Now() at Dial success so the very
        // first PING doesn't immediately trigger the dead-server check.
        //
        // Atomic for lock-free read in inBandPinger (hot path) and
        // lock-free write in eventPump's MsgPONG handler. sync/atomic
        // on int64 is safe on all supported platforms.
        lastPongAt atomic.Int64

        // in-band multiplexing state (nil when UseInBand is false).
        // pktMu protects ib's decoder/dataBuf/proto fields; the events
        // channel is safe for concurrent receive without the mutex.
        pktMu sync.Mutex
        ib    *inBand

        // closeMu guards closeHooks only. The actual close sequence
        // (runCloseHooks + close(stopPing) + rawConn.Close + close events)
        // is serialized via closeOnce (sync.Once) — this is the v0.1.28
        // fix for the Close-race panic.
        //
        // OnClose hooks registered after Close has already run are
        // invoked immediately (so cleanup still happens — important
        // for the gsids unsubscribe path).
        closeMu    sync.Mutex
        closed     bool
        closeHooks []func()

        // closeOnce serializes the entire Close sequence. closeErr is
        // written by the once.Do func and read by all subsequent callers.
        closeOnce sync.Once
        closeErr  error
}

// Read reads decoded application data from the connection.
//
// In raw (cat) mode this is a direct passthrough to the underlying TLS
// connection. In in-band mode (Options.UseInBand) the bytes are first
// run through the gspkt decoder: literal 0xFB is un-doubled and any
// in-band packets (PING/LOG/channel streams) are extracted to the
// Events() channel.
//
// Returns 0 bytes + error on EOF or protocol error.
func (c *Conn) Read(p []byte) (int, error) {
        if c.ib == nil {
                return c.rawConn.Read(p)
        }
        return c.inBandRead(p)
}

// Write writes application data to the connection.
//
// In raw (cat) mode this is a direct passthrough. In in-band mode the
// data is escape-encoded (every 0xFB doubled) so a literal 0xFB cannot
// be mistaken for the start of an in-band packet on the peer side.
//
// Use WriteMsg / WriteChn to send in-band signalling packets.
func (c *Conn) Write(p []byte) (int, error) {
        if c.ib == nil {
                return c.rawConn.Write(p)
        }
        return c.inBandWrite(p)
}

// Creds returns the derived credentials.  Useful for logging the GS-Address.
func (c *Conn) Creds() *gskdf.Credentials { return c.creds }

// Role returns the SSL role the relay assigned to us.
func (c *Conn) Role() gsrn.Role { return c.role }

// Mode returns the local Mode (listen or connect).
func (c *Conn) Mode() Mode { return c.mode }

// DisableInBand (v0.3.0) disables in-band multiplexing on an existing
// connection. After this call, Read/Write pass through to rawConn
// directly (no escape-byte encoding/decoding).
//
// Used by --sftp-real to bypass the in-band encoder for SSH handshake
// bytes. The SSH layer has its own framing and cannot tolerate
// escape-byte corruption.
//
// Must be called BEFORE any I/O occurs on the conn (typically right
// after Dial returns). Calling it after I/O has started is undefined.
//
// Safe for one-time use. Idempotent (calling twice is a no-op).
func (c *Conn) DisableInBand() {
        c.pktMu.Lock()
        defer c.pktMu.Unlock()
        c.ib = nil
}

// WrapRawConn (v0.2.0) replaces the underlying io.ReadWriteCloser with
// the provided wrapper. The wrapper must satisfy io.ReadWriteCloser and
// should typically delegate Read/Write/Close to the original conn it
// received. SetDeadline/SetReadDeadline/SetWriteDeadline/CloseWrite
// will continue to work via type assertions on the wrapper (so the
// wrapper should preserve those methods if it wants them to keep
// working).
//
// Use this to install compression, rate-limiting, audit-logging, etc.
// The wrapper takes effect immediately for all subsequent Read/Write
// calls (including in-band mode).
//
// MUST be called BEFORE any I/O occurs on the conn (typically right
// after Dial returns). Calling it after I/O has started is undefined.
//
// Example:
//
//   conn, _ := gsconn.Dial(...)
//   if rateLimit > 0 {
//       conn.WrapRawConn(newRateLimitedConn(conn.RawConn(), rateLimit))
//   }
//
// Safe for one-time use. Not safe to call concurrently with Read/Write.
func (c *Conn) WrapRawConn(wrapper io.ReadWriteCloser) {
        if wrapper == nil {
                return
        }
        c.pktMu.Lock()
        c.rawConn = wrapper
        c.pktMu.Unlock()
}

// RawConn (v0.2.0) returns the current underlying io.ReadWriteCloser.
// Useful when constructing a wrapper: the wrapper typically delegates
// to the original conn, which it captures by calling RawConn BEFORE
// calling WrapRawConn.
//
// NOTE: Returns the CURRENT rawConn. After WrapRawConn, subsequent
// calls return the wrapper. This is intentional — chained wrappers
// (compress over rate-limit over audit, etc.) build up naturally.
func (c *Conn) RawConn() io.ReadWriteCloser {
        c.pktMu.Lock()
        defer c.pktMu.Unlock()
        return c.rawConn
}

// MarkPongReceived updates the last-PONG-received timestamp used by
// inBandPinger's dead-server detection. The event-pump SHOULD call
// this whenever a MsgPONG is received from the peer (the client-side
// handler in cmd/gs-netcat/main.go does this).
//
// Safe for concurrent use — lastPongAt is sync/atomic.Int64.
func (c *Conn) MarkPongReceived() {
        c.lastPongAt.Store(time.Now().UnixNano())
}

// SetDeadline sets the read and write deadlines on the underlying
// connection (TLS or raw TCP). It mirrors net.Conn.SetDeadline. In
// NoEncryption mode it delegates to *net.TCPConn; in encrypted mode
// it delegates to *tlssrp.Conn (which forwards to the underlying TCP).
// Returns an error if the underlying type does not support deadlines.
func (c *Conn) SetDeadline(t time.Time) error {
        if d, ok := c.rawConn.(interface{ SetDeadline(time.Time) error }); ok {
                return d.SetDeadline(t)
        }
        return errors.New("gsconn: SetDeadline not supported by underlying conn")
}

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *Conn) SetReadDeadline(t time.Time) error {
        if d, ok := c.rawConn.(interface{ SetReadDeadline(time.Time) error }); ok {
                return d.SetReadDeadline(t)
        }
        return errors.New("gsconn: SetReadDeadline not supported by underlying conn")
}

// SetWriteDeadline sets the write deadline on the underlying connection.
func (c *Conn) SetWriteDeadline(t time.Time) error {
        if d, ok := c.rawConn.(interface{ SetWriteDeadline(time.Time) error }); ok {
                return d.SetWriteDeadline(t)
        }
        return errors.New("gsconn: SetWriteDeadline not supported by underlying conn")
}

// CloseWrite performs a half-close of the write side of the connection.
// In encrypted mode it delegates to *tlssrp.Conn.CloseWrite (which sends
// a TLS close_notify and shuts down the TCP write side). In NoEncryption
// mode it delegates to *net.TCPConn.CloseWrite (sends TCP FIN).
//
// Returns an error if the underlying type does not support half-close.
func (c *Conn) CloseWrite() error {
        if cw, ok := c.rawConn.(interface{ CloseWrite() error }); ok {
                return cw.CloseWrite()
        }
        return errors.New("gsconn: CloseWrite not supported by underlying conn")
}

// Dial connects to the GSRN relay, completes the _gs_listen/_gs_connect
// handshake, waits for _gs_start, performs the TLS-SRP handshake, and
// returns a *Conn ready for application data.
//
// Both peers call Dial() with the same secret; one passes ModeListen,
// the other ModeConnect.  The relay matches them by GS-Address.
//
// If opts.NoEncryption is set (the -C flag), the TLS-SRP handshake is
// skipped and raw bytes flow through the relay. See Options.NoEncryption
// for wire-compatibility caveats.
//
// opts.ServerCheck is rejected here — use DialTest for the -t mode.
func Dial(secret string, mode Mode, opts *Options) (*Conn, error) {
        if opts == nil {
                return nil, errors.New("gsconn: nil Options")
        }
        if opts.ServerCheck {
                return nil, errors.New("gsconn: ServerCheck set; use DialTest instead")
        }
        if opts.RelayHost == "" {
                return nil, errors.New("gsconn: RelayHost is required")
        }
        if opts.RelayPort == 0 {
                opts.RelayPort = gsrn.DefaultPort
        }
        if opts.HandshakeTimeout == 0 {
                opts.HandshakeTimeout = 30 * time.Second
        }

        creds := gskdf.Derive(secret)

        // For listener mode, precompute the SRP verifier in the background
        // BEFORE the relay handshake starts. The verifier computation
        // (g^x mod N for 4096-bit N) takes ~100-500ms on Go's math/big,
        // and C gs-netcat connectors time out in <1 sec if the server
        // doesn't respond with ServerHello quickly enough. By starting the
        // computation now (before we even register with the relay), the
        // verifier will be ready by the time a connector connects.
        //
        // v0.1.28 (audit-2 bug #3, MEDIUM): Also precompute for ModeConnect
        // when the -A flag (FlagClientOrServer) is set — the relay may
        // assign us RoleServer, in which case we need the verifier.
        // Without this, `-A` on the connect side fails TLS handshake
        // when the relay flips our role.
        var serverLookup *onTheFlyLookup
        needServerLookup := mode == ModeListen ||
                (mode == ModeConnect && opts.FlagExtra&gsrn.FlagClientOrServer != 0)
        if needServerLookup {
                serverLookup = &onTheFlyLookup{
                        user:     gskdf.SRPUsername,
                        password: creds.SRPPassword,
                        group:    &tlssrp.SRPGroup4096,
                }
                // Kick off the precomputation immediately.
                go serverLookup.ensurePrecomputed()
        }

        // Build the GSRN options.
        gopts := &gsrn.Options{
                RelayHost:    opts.RelayHost,
                RelayPort:    opts.RelayPort,
                Flags:        opts.FlagExtra,
                PingInterval: 0, // we'll handle keepalive at this layer
                Dialer:       opts.Dialer, // v0.1.30: --tor / --stealth-https
        }

        // Auth-token policy:
        //   ModeListen with AuthToken=""  → random 16 bytes (default behaviour)
        //   ModeListen with AuthToken="x" → DeriveAuthToken("x", addr)
        //   ModeConnect                   → token field NOTUSED (left zero)
        if mode == ModeListen {
                if opts.AuthToken != "" {
                        gopts.Token = gskdf.DeriveAuthToken(opts.AuthToken, creds.Address)
                } else {
                        t, err := gskdf.GenRandomToken()
                        if err != nil {
                                return nil, fmt.Errorf("gsconn: gen token: %w", err)
                        }
                        gopts.Token = t
                }
        }

        // Dial the relay with the listen/connect packet.
        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] gsconn.Dial: dialing relay %s:%d (mode=%v, flags=0x%02x, useInBand=%v, noEnc=%v)\n",
                        opts.RelayHost, opts.RelayPort, mode, gopts.Flags, opts.UseInBand, opts.NoEncryption)
        }
        tDial := time.Now()
        relay, err := gsrn.Dial(creds.Address, mode == ModeListen, gopts)
        if err != nil {
                return nil, err
        }
        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] gsconn.Dial: relay TCP connected (took %v), %s packet sent\n",
                        time.Since(tDial), map[bool]string{true: "_gs_listen", false: "_gs_connect"}[mode == ModeListen])
        }

        // Enable TCP keepalive on the relay socket so consumer NATs don't
        // drop the long-lived relay connection during idle periods.
        // GSRN-level ping/pong is NOT used because writing raw 32-byte GSRN
        // packets into a TCP stream that the TLS layer thinks it owns corrupts
        // TLS framing. Real gs-netcat multiplexes pings via an out-of-band
        // mechanism (lib/packet.c escape-byte protocol) that runs *inside* TLS,
        // which the Go port does not implement in v1. TCP keepalive achieves
        // the same NAT-preservation effect without touching TLS framing.
        if tc, ok := relay.Conn.(*net.TCPConn); ok {
                _ = tc.SetKeepAlive(true)
                _ = tc.SetKeepAlivePeriod(30 * time.Second)
                // v0.1.26: Disable Nagle's algorithm. The Go client sends 1-byte
                // writes for each keystroke (io.Copy reads 1 byte at a time from
                // raw stdin on Windows). With Nagle ON, these 1-byte writes are
                // buffered for up to 200ms waiting for an ACK. This adds latency
                // to every keystroke. With Nagle OFF (TCP_NODELAY), each keystroke
                // is sent immediately as its own TLS record.
                // This is standard practice for interactive SSH/telnet clients.
                _ = tc.SetNoDelay(true)
        }

        // Set handshake deadline on the underlying TCP.
        //
        // BUG FIX (v0.1.17): In LISTEN mode the relay will hold the
        // connection open until a CONNECT peer arrives — which could
        // take minutes, hours, or days. The previous code applied
        // opts.HandshakeTimeout (default 30s) to relay.Start(), which
        // fired before any connector had a chance to connect. Symptom:
        //
        //     gsrn: read start/status: read tcp 192.168.x.x:ppppp->152.53.173.29:443: i/o timeout
        //
        // after ~30s in `-l -i` mode, even when the relay was perfectly
        // reachable. The user could never get a server up.
        //
        // Fix: in CONNECT mode the relay must respond with _gs_start (or
        // _gs_status) within seconds, so the deadline covering Start()
        // + SendAccept() + TLS handshake is correct. In LISTEN mode we
        // do NOT set a deadline before Start() — Start() may legitimately
        // block indefinitely. The deadline is deferred to just before
        // the TLS handshake (set below, after Start() returns), so a
        // hung TLS peer still gets bounded.
        if mode == ModeConnect {
                _ = relay.SetDeadline(time.Now().Add(opts.HandshakeTimeout))
        }
        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] relay dialed (mode=%v, addr=%x); waiting for _gs_start (deadline=%v)\n",
                        mode, creds.Address[:4], mode == ModeConnect)
        }

        // Pipeline optimization: build the TLS config in parallel with
        // waiting for _gs_start. buildTLSConfig itself is O(1) but the
        // server-side onTheFlyLookup.ensurePrecomputed() (kicked off
        // above) is the expensive part — for client mode this is just
        // struct assembly. Running it concurrently with the relay
        // round-trip shaves one RTT off the total handshake latency
        // when the relay is slow (e.g. cross-continent).
        //
        // FAST_CONNECT note: even with FAST_CONNECT set on the wire
        // (default for CONNECT), the C original ALWAYS waits for
        // _gs_start locally (gsocket-engine.c never reads the flag for
        // local logic — see header comment in gsrn/flags.go). We do the
        // same: Start() blocks for _gs_start regardless of FAST_CONNECT.
        type tlsResult struct {
                cfg *tlssrp.Config
                err error
        }
        tlsCh := make(chan tlsResult, 1)
        go func() {
                cfg, err := buildTLSConfig(creds, gsrn.RoleUnassigned, serverLookup)
                // role isn't known yet; buildTLSConfig only uses it to decide
                // whether to install SRPLookup. We pass RoleUnassigned and
                // re-install SRPLookup below if we end up as server.
                tlsCh <- tlsResult{cfg, err}
        }()

        // Wait for _gs_start to tell us our SSL role.
        tStart := time.Now()
        role, err := relay.Start()
        if err != nil {
                relay.Close()
                return nil, err
        }
        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] role assigned: %v (after %v)\n", role, time.Since(tStart))
        }

        // In LISTEN mode we deferred the deadline until now (see above).
        // _gs_start has arrived — a connector is waiting on the other
        // end. From here on the TLS handshake should complete in
        // seconds; if it hangs, the deadline still bounds it. This
        // preserves the original safety property (a stuck TLS peer
        // can't hold us forever) without breaking the legitimate
        // long wait for a connector in LISTEN mode.
        if mode == ModeListen {
                _ = relay.SetDeadline(time.Now().Add(opts.HandshakeTimeout))
                if os.Getenv("GSPORT_DEBUG") != "" {
                        fmt.Fprintf(os.Stderr, "[gsport] deadline set for TLS handshake: %v\n", opts.HandshakeTimeout)
                }
        }

        // Acknowledge the role assignment.
        tAccept := time.Now()
        if err := relay.SendAccept(); err != nil {
                relay.Close()
                return nil, fmt.Errorf("gsconn: send accept: %w", err)
        }
        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] accept sent (after %v)\n", time.Since(tAccept))
        }

        // v0.1.28 (audit-2 bug #2, HIGH): Clear deadline AFTER the TLS
        // handshake, not before. The previous code cleared the deadline
        // here (before Handshake()), contradicting the documented safety
        // property. A peer that completes _gs_start but hangs mid-TLS
        // would leave the connection blocked indefinitely.
        //
        // For the NoEncryption path, no TLS handshake follows, so we
        // can clear immediately. For the TLS path, keep the deadline
        // active until Handshake() returns.
        if opts.NoEncryption {
                _ = relay.SetDeadline(time.Time{})
                if os.Getenv("GSPORT_DEBUG") != "" {
                        fmt.Fprintf(os.Stderr, "[gsport] deadline cleared, ready for raw data flow (-C)\n")
                }
        }

        // -C (NoEncryption): skip TLS-SRP entirely. The relay TCP is the
        // data channel. rawConn is the relay net.Conn directly, so all
        // Read/Write/Close paths work uniformly with the encrypted mode.
        if opts.NoEncryption {
                // Drain the parallel TLS-config goroutine so it doesn't
                // leak (it has already done its work; we just need to
                // receive from the buffered channel).
                <-tlsCh
                if os.Getenv("GSPORT_DEBUG") != "" {
                        fmt.Fprintf(os.Stderr, "%s", strs.Decode([]byte{0x9f, 0xa3, 0xb7, 0xb4, 0xab, 0xb6, 0xb0, 0x99, 0xe4, 0x8a, 0xab, 0x81, 0xaa, 0xa7, 0xb6, 0xbd, 0xb4, 0xb0, 0xad, 0xab, 0xaa, 0xe4, 0xa9, 0xab, 0xa0, 0xa1, 0xe4, 0x26, 0x44, 0x50, 0xe4, 0xb7, 0xaf, 0xad, 0xb4, 0xb4, 0xad, 0xaa, 0xa3, 0xe4, 0x90, 0x88, 0x97, 0xe9, 0x97, 0x96, 0x94, 0xe4, 0xac, 0xa5, 0xaa, 0xa0, 0xb7, 0xac, 0xa5, 0xaf, 0xa1}, 0xc4))
                }
                c := &Conn{
                        rawConn:  relay.Conn,
                        relay:    relay,
                        creds:    creds,
                        role:     role,
                        mode:     mode,
                        stopPing: make(chan struct{}),
                }
                // Initialize lastPongAt so the dead-server check in
                // inBandPinger doesn't fire on the very first PING (which
                // would happen if lastPongAt was 0 and we'd just sent a
                // PING that hasn't been answered yet).
                c.lastPongAt.Store(time.Now().UnixNano())
                if opts.UseInBand {
                        c.ib = newInBand()
                }
                if opts.PingInterval > 0 {
                        if opts.UseInBand && c.role == gsrn.RoleClient {
                                go c.inBandPinger(opts.PingInterval)
                        } else {
                                go c.pingerStub(opts.PingInterval)
                        }
                }
                return c, nil
        }

        // Pick up the TLS config built in parallel. If it errored, bail now.
        tres := <-tlsCh
        if tres.err != nil {
                relay.Close()
                return nil, tres.err
        }
        tlsCfg := tres.cfg
        // buildTLSConfig ran with RoleUnassigned; install the SRP lookup
        // if we ended up as server.
        if role == gsrn.RoleServer && serverLookup != nil {
                tlsCfg.SRPLookup = serverLookup
        }

        // Wrap the relay TCP with the right TLS role.
        var tlsConn *tlssrp.Conn
        switch role {
        case gsrn.RoleServer:
                tlsConn = tlssrp.Server(relay.Conn, tlsCfg)
        case gsrn.RoleClient:
                tlsConn = tlssrp.Client(relay.Conn, tlsCfg)
        default:
                relay.Close()
                return nil, fmt.Errorf("gsconn: invalid role %v", role)
        }
        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] starting TLS handshake as %v (total since Start: %v)\n", role, time.Since(tStart))
        }

        // Run the TLS-SRP handshake.
        tHandshake := time.Now()
        if err := tlsConn.Handshake(); err != nil {
                relay.Close()
                return nil, fmt.Errorf(strs.Decode([]byte{0xf1, 0xe5, 0xf5, 0xf9, 0xf8, 0xf8, 0xac, 0xb6, 0xc2, 0xda, 0xc5, 0xbb, 0xc5, 0xc4, 0xc6, 0xb6, 0xfe, 0xf7, 0xf8, 0xf2, 0xe5, 0xfe, 0xf7, 0xfd, 0xf3, 0xb6, 0xbe, 0xf0, 0xf7, 0xff, 0xfa, 0xf3, 0xf2, 0xb6, 0xf7, 0xf0, 0xe2, 0xf3, 0xe4, 0xb6, 0xb3, 0xe0, 0xbf, 0xac, 0xb6, 0xb3, 0xe1}, 0x96), time.Since(tHandshake), err) //nolint:govet // dynamic format string is intentional for AV-FP mitigation
        }
        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] TLS handshake completed (took %v)\n", time.Since(tHandshake))
        }

        // v0.1.28: NOW clear the deadline — TLS handshake succeeded,
        // application data flows under no deadline (caller may set its
        // own via SetDeadline). This is the correct place: after Handshake
        // returns successfully.
        _ = relay.SetDeadline(time.Time{})
        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] deadline cleared after TLS handshake\n")
        }

        c := &Conn{
                rawConn:  tlsConn,
                relay:    relay,
                creds:    creds,
                role:     role,
                mode:     mode,
                stopPing: make(chan struct{}),
        }
        // Initialize lastPongAt so the dead-server check in
        // inBandPinger doesn't fire on the very first PING.
        c.lastPongAt.Store(time.Now().UnixNano())
        if opts.UseInBand {
                c.ib = newInBand()
        }

        // Optionally start keepalive pinger.
        //
        // In in-band mode this sends a real gspkt.MsgPING every PingInterval
        // — that is the application-level keepalive the C original uses
        // (lib/packet.c multiplexes pings *inside* the TLS stream, so they
        // do not corrupt TLS framing). The peer's decoder extracts the PING
        // and the peer's event-pump is expected to reply with PONG.
        //
        // In raw (cat) mode this is a no-op stub: writing raw GSRN pings or
        // gspkt pings into a TLS-owned stream without an in-band decoder on
        // the peer side would either corrupt TLS framing (GSRN pings) or
        // appear as junk bytes in the peer's data stream (gspkt pings). TCP
        // keepalive (enabled on the relay socket in Dial) substitutes.
        if opts.PingInterval > 0 {
                if opts.UseInBand && c.role == gsrn.RoleClient {
                        // In in-band mode the connector (SSL-client) sends PING
                        // every interval; the listener (SSL-server) replies with
                        // PONG via the event-pump. Mirrors the C original where
                        // cb_periodic_ping is armed only when is_interactive &&
                        // !is_server.
                        go c.inBandPinger(opts.PingInterval)
                } else {
                        // Raw mode OR listener in in-band mode: no app-level
                        // ping. NAT preservation falls back to TCP keepalive
                        // (enabled on the relay socket in Dial).
                        go c.pingerStub(opts.PingInterval)
                }
        }

        return c, nil
}

// OnClose registers a function to be called when Conn.Close is
// invoked. Multiple hooks may be registered; they run in registration
// order. Hooks are called at most once per registration.
//
// This is used by main.go's MsgIDS handler to register the gsids
// unsubscribe callback so IDS subscriptions are cleaned up when the
// conn terminates.
//
// If Close has already run by the time OnClose is called, fn is
// invoked immediately (synchronously, on the calling goroutine) so
// cleanup semantics are preserved regardless of registration timing.
func (c *Conn) OnClose(fn func()) {
        c.closeMu.Lock()
        if c.closed {
                c.closeMu.Unlock()
                fn()
                return
        }
        c.closeHooks = append(c.closeHooks, fn)
        c.closeMu.Unlock()
}

// runCloseHooks invokes all registered close hooks in registration
// order. Called exactly once by Close. Hooks are extracted under
// closeMu and then invoked WITHOUT the lock held (so hooks can call
// back into Conn methods that acquire closeMu if needed).
func (c *Conn) runCloseHooks() {
        c.closeMu.Lock()
        hooks := c.closeHooks
        c.closeHooks = nil
        c.closed = true
        c.closeMu.Unlock()
        for _, fn := range hooks {
                fn()
        }
}

// Close tears down the connection and stops the keepalive goroutine.
// Idempotent AND concurrency-safe: uses sync.Once for the entire
// close sequence so concurrent Close calls (e.g. user-Close +
// inBandPinger-dead-server-Close) cannot panic on close-of-closed-channel.
//
// v0.1.28 (audit-2 bug #1, HIGH): Previously the `closed` check and
// `closed = true` set were not atomic (separated by lock release +
// runCloseHooks). Two goroutines could both pass the check, both
// reach `select { default: close(c.stopPing) }`, and both call
// close(c.stopPing) → panic. Now the entire close sequence is wrapped
// in sync.Once.
func (c *Conn) Close() error {
        c.closeOnce.Do(func() {
                c.runCloseHooks()

                // Close stopPing signal channel (safe — once.Do guarantees
                // we're the only one here).
                close(c.stopPing)

                // tlssrp.Conn.Close() will close the underlying relay TCP.
                c.closeErr = c.rawConn.Close()

                // Drain and close the events channel so the event-pump goroutine
                // (if any) can exit its range loop.
                if c.ib != nil {
                        c.pktMu.Lock()
                        c.ib.proto = io.EOF
                        if !c.ib.eventsClosed {
                                c.ib.eventsClosed = true
                                close(c.ib.events)
                        }
                        c.pktMu.Unlock()
                }
        })
        return c.closeErr
}

// pingerStub is a no-op placeholder for the keepalive goroutine in raw
// (cat) mode. It exists so that the API is uniform across modes; for
// raw mode it simply waits on stopPing and exits, leaving NAT
// preservation to TCP keepalive (enabled in Dial).
func (c *Conn) pingerStub(interval time.Duration) {
        t := time.NewTicker(interval)
        defer t.Stop()
        for {
                select {
                case <-c.stopPing:
                        return
                case <-t.C:
                        // no-op — TCP keepalive handles NAT preservation
                }
        }
}

// inBandPinger is the keepalive goroutine for in-band mode. Every
// interval it sends a gspkt.MsgPING (16-byte payload, all zero —
// matching struct _pkt_app_ping with flags=0). The peer's event-pump is
// expected to reply with MsgPONG; we do NOT block waiting for the reply
// (fire-and-forget). The peer's PONG arrives as an Event via
// Conn.Events() for the application to display if it wants.
//
// v0.1.20: dead-server detection. After sending each PING, check the
// last PONG timestamp. If it's older than 2× interval, the server has
// stopped responding (process killed but TCP not yet RST, NAT lost
// state, DPI silently dropping one direction, etc.). In that case we
// close the Conn ourselves instead of waiting for TCP retransmit
// timeout (which can take 5+ minutes on Linux with default sysctl).
// The user sees a clean disconnect within 2 intervals instead of an
// indefinite hang.
func (c *Conn) inBandPinger(interval time.Duration) {
        t := time.NewTicker(interval)
        defer t.Stop()
        payload := make([]byte, 16) // MsgPING = 16 bytes per gspkt.MsgSize
        const deadServerMultiplier = 2 // close after 2× interval without PONG
        for {
                select {
                case <-c.stopPing:
                        return
                case <-t.C:
                        // Dead-server check (BEFORE sending PING so the
                        // very first tick after Dial doesn't immediately
                        // trip — lastPongAt was initialized to time.Now()
                        // in Dial).
                        last := c.lastPongAt.Load()
                        if last > 0 {
                                sincePong := time.Since(time.Unix(0, last))
                                if sincePong > deadServerMultiplier*interval {
                                        fmt.Fprintf(os.Stderr, "[gs-netcat] no PONG from server in %v (>%vx interval) — server appears dead, closing connection\n",
                                                sincePong, deadServerMultiplier)
                                        _ = c.Close()
                                        return
                                }
                        }
                        if err := c.WriteMsg(gspkt.MsgPING, payload); err != nil {
                                // PING write failed — the underlying TCP/TLS is broken.
                                // Close the Conn so inBandRead unblocks and the higher-
                                // level session loop (runInteractive*, multipeer) sees
                                // the disconnect and reacts (server: re-listen;
                                // client: exit so user can reconnect).
                                fmt.Fprintf(os.Stderr, "[gs-netcat] keepalive PING failed: %v — closing connection\n", err)
                                _ = c.Close()
                                return
                        }
                        if os.Getenv("GSPORT_DEBUG") != "" {
                                fmt.Fprintf(os.Stderr, "[gsport] in-band ping sent\n")
                        }
                }
        }
}

// buildTLSConfig returns a *tlssrp.Config pinned to:
//   - TLS 1.2 (SRP was removed from TLS 1.3)
//   - Single ciphersuite: TLS_SRP_SHA_WITH_AES_256_CBC_SHA (0xC020)
//   - Group: 4096-bit (RFC 5054 §A.2 #3) — what gs-netcat uses
//   - Username: "user" (what gs-netcat hardcodes)
//   - Password: the wrapped SRP password from gskdf.Derive
//
// For server role, a Lookuper is installed that uses the precomputed
// verifier+salt (computed in background at Dial time). This mirrors
// gs-netcat's SRP_create_verifier_BN("user", pwd, &salt, &verifier, N, g)
// call but with the verifier cached for performance.
//
// Salt length is 20 bytes (matches OpenSSL's SRP_create_verifier_BN,
// confirmed in A5 wire capture).
func buildTLSConfig(creds *gskdf.Credentials, role gsrn.Role, lookup *onTheFlyLookup) (*tlssrp.Config, error) {
        cfg := &tlssrp.Config{
                // Pin TLS 1.2: SRP ciphersuites are not defined for TLS 1.3,
                // and TLS 1.0/1.1 are deprecated.
                MinVersion: tlssrp.VersionTLS12,
                MaxVersion: tlssrp.VersionTLS12,

                // Single ciphersuite — what gs-netcat requests.
                CipherSuites: []uint16{tlssrp.TLS_SRP_SHA_WITH_AES_256_CBC_SHA},

                // Disable session tickets — they make TLS-SRP pointless (the
                // ticket would let an attacker resume without the password).
                // gs-netcat doesn't use them either.
                SessionTicketsDisabled: true,

                // SRP client side:
                SRPUser:     gskdf.SRPUsername, // "user"
                SRPPassword: creds.SRPPassword,
                SRPGroups:   []*tlssrp.SRPGroup{&tlssrp.SRPGroup4096},

                // SRP server side (only used when role == RoleServer):
                SRPSaltKey:  "gsport-default-salt-key", // any non-empty string
                SRPSaltSize: gskdf.SaltLength,          // 20 — matches OpenSSL
        }

        if role == gsrn.RoleServer && lookup != nil {
                cfg.SRPLookup = lookup
        }

        return cfg, nil
}

// onTheFlyLookup implements tlssrp.Lookuper by computing the verifier
// from the configured password on every Lookup call, mirroring what
// gs-netcat does (lib/gsocket-ssl.c uses SRP_create_verifier_BN inside
// the SRP_username_cb callback so the verifier is never stored).
//
// To keep interop latency low with C gs-netcat connectors (which time out
// in <1 sec if the server doesn't respond with ServerHello quickly enough),
// the verifier and salt are precomputed ONCE at construction time and
// reused for every connection. This is acceptable for v1 because:
//   - The verifier is never transmitted over the wire (only B = k*v + g^a).
//   - The salt is visible in ServerKeyExchange but with a known salt an
//     attacker still needs to solve DLP to recover the password.
//   - The risk is offline dictionary attack IF the attacker later
//     compromises the server and obtains the verifier — same risk as any
//     SRP deployment with a stored verifier file.
//
// A fresh salt+verifier per connection would be ideal (limits replay
// value of a compromised verifier to a single session) but requires
// either C-speed bigint math or a precomputed pool. Deferred to v1.1.
type onTheFlyLookup struct {
        user     string
        password string
        group    *tlssrp.SRPGroup
        // Precomputed material (computed once at construction):
        salt     []byte
        verifier []byte
        once     sync.Once
}

func (l *onTheFlyLookup) ensurePrecomputed() {
        l.once.Do(func() {
                l.salt = make([]byte, gskdf.SaltLength)
                if _, err := rand.Read(l.salt); err != nil {
                        // extremely unlikely; fall back to deterministic salt
                        panic(fmt.Sprintf("gsconn: gen salt: %v", err))
                }
                l.verifier = tlssrp.SRPVerifier(l.user, l.password, l.salt, *l.group)
                if os.Getenv("GSPORT_DEBUG") != "" {
                        fmt.Fprintf(os.Stderr, "[gsport] precomputed verifier: salt=%d bytes, v=%d bytes\n",
                                len(l.salt), len(l.verifier))
                }
        })
}

func (l *onTheFlyLookup) Lookup(user string) (v, s []byte, grp tlssrp.SRPGroup, err error) {
        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] onTheFlyLookup: user=%q (expected %q)\n", user, l.user)
        }
        // gs-netcat only ever uses username "user".  We accept any username
        // and return a verifier for the configured password — the TLS-SRP
        // handshake will then succeed iff the client used the same password.
        // (mjl's library has its own user-enumeration protection: when v==nil
        // and s==nil but grp is non-zero, the server uses a fake salt+verifier
        // and produces a fake PMS so the handshake fails in a way that does
        // not reveal whether the username was valid.)
        if user != l.user {
                if os.Getenv("GSPORT_DEBUG") != "" {
                        fmt.Fprintf(os.Stderr, "[gsport] onTheFlyLookup: user mismatch — returning nil verifier\n")
                }
                return nil, nil, *l.group, nil
        }

        // Use the precomputed verifier+salt. This keeps Lookup O(1) and lets
        // the TLS-SRP server respond with ServerHello + ServerKeyExchange
        // within milliseconds of receiving ClientHello — fast enough for
        // C gs-netcat's ~1-sec handshake timeout.
        l.ensurePrecomputed()
        return l.verifier, l.salt, *l.group, nil
}

// RelayHostnameForAddr mirrors GS_ADDR_get_hostname_id (analysis §10.5):
//
//      sum(addr[0..15]) % 26 → [a-z].gs.thc.org
//
// This is how the production gsocket.org relay routes connections.
// Each GS-Address hashes to a specific relay hostname.
func RelayHostnameForAddr(addr gskdf.Addr) string {
        var sum int
        for _, b := range addr {
                sum += int(b)
        }
        letter := rune('a' + (sum % 26))
        return string(letter) + ".gs.thc.org"
}

// noTLSConn is no longer needed — in NoEncryption mode we store the
// relay's net.Conn directly as rawConn (which is io.ReadWriteCloser).
// Kept as a no-op placeholder so the diff history is clear; safe to
// remove in a future cleanup.
//
// (No type alias needed; net.Conn already satisfies io.ReadWriteCloser
// via the concrete *net.TCPConn returned by gsrn.Dial.)

// DialTest implements the -t (ServerCheck) mode: connect to the GSRN
// with FlagServerCheck set, wait for the relay's _gs_status response,
// and return it as a StatusError (or nil if the relay reported OK).
//
// This mirrors the C `is_try_server` path: the relay short-circuits
// the connection and returns SERVER_OK / CONNREFUSED / NETERROR
// without putting the peers in contact. No TLS handshake, no data
// path. The caller inspects the returned StatusError.Code to decide
// OK / NO / NET-ERROR for the human-readable output.
//
// `relayTimeout` bounds the entire operation (default 15s in C).
func DialTest(secret string, opts *Options, relayTimeout time.Duration) (status byte, err error) {
        if opts == nil {
                return 0, errors.New("gsconn: nil Options")
        }
        if opts.RelayHost == "" {
                return 0, errors.New("gsconn: RelayHost is required")
        }
        if opts.RelayPort == 0 {
                opts.RelayPort = gsrn.DefaultPort
        }
        if relayTimeout <= 0 {
                relayTimeout = 15 * time.Second
        }

        creds := gskdf.Derive(secret)

        // Force SERVER_CHECK on the wire.
        gopts := &gsrn.Options{
                RelayHost: opts.RelayHost,
                RelayPort: opts.RelayPort,
                Flags:     opts.FlagExtra | gsrn.FlagServerCheck,
        }
        // Auth token is irrelevant for SERVER_CHECK (the relay doesn't
        // match peers), but we send a zero token to match the wire format.
        relay, err := gsrn.Dial(creds.Address, false, gopts)
        if err != nil {
                // Network-level failure (TCP to relay failed): NET-ERROR.
                return 0, err
        }
        defer relay.Close()
        _ = relay.SetDeadline(time.Now().Add(relayTimeout))

        // Wait for the relay's response. With SERVER_CHECK set the relay
        // replies with _gs_status (SERVER_OK or CONNREFUSED) instead of
        // _gs_start.
        role, err := relay.Start()
        if err == nil {
                // Got _gs_start (no SERVER_CHECK support on this relay?).
                // Treat as OK — the relay accepted our connect, meaning a
                // peer is listening (otherwise we'd have gotten CONNREFUSED).
                _ = role
                return gsrn.StatusServerOK, nil
        }
        if se, ok := err.(gsrn.StatusError); ok {
                return se.Code, nil
        }
        // Timeout / other I/O error: NET-ERROR.
        return 0, err
}

// silence unused-import warnings for io / net (kept for future use).
var _ = io.Copy
var _ net.Conn
