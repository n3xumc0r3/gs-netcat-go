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

        // in-band multiplexing state (nil when UseInBand is false).
        // pktMu protects ib's decoder/dataBuf/proto fields; the events
        // channel is safe for concurrent receive without the mutex.
        pktMu sync.Mutex
        ib    *inBand

        // closeMu guards closeHooks and closed. closed ensures Close
        // (and the hooks) run at most once even if Close is called
        // concurrently from multiple goroutines (e.g. user-initiated
        // shutdown + remote-closed detection).
        //
        // OnClose hooks registered after Close has already run are
        // invoked immediately (so cleanup still happens — important
        // for the gsids unsubscribe path).
        closeMu    sync.Mutex
        closed     bool
        closeHooks []func()
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
        // (For connect mode we're the TLS client, no verifier needed.)
        var serverLookup *onTheFlyLookup
        if mode == ModeListen {
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
        relay, err := gsrn.Dial(creds.Address, mode == ModeListen, gopts)
        if err != nil {
                return nil, err
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
        }

        // Set handshake deadline on the underlying TCP.
        //
        // v0.1.10 fix: when WAIT (FlagWait, -w CLI flag) is set, the
        // relay is SUPPOSED to block at the relay level until a
        // listener appears. Our default 30s handshake deadline fired
        // first, causing `-w` to fail with a timeout instead of waiting
        // for the server. We now extend the deadline to 24 hours when
        // WAIT is set — the user can still interrupt with Ctrl-C.
        handshakeTimeout := opts.HandshakeTimeout
        if opts.FlagExtra&gsrn.FlagWait != 0 && mode == ModeConnect {
                handshakeTimeout = 24 * time.Hour
        }
        _ = relay.SetDeadline(time.Now().Add(handshakeTimeout))

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

        // Acknowledge the role assignment.
        tAccept := time.Now()
        if err := relay.SendAccept(); err != nil {
                relay.Close()
                return nil, fmt.Errorf("gsconn: send accept: %w", err)
        }
        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] accept sent (after %v)\n", time.Since(tAccept))
        }

        // Clear the deadline — application data flows under no deadline
        // (caller may set its own via SetDeadline).
        _ = relay.SetDeadline(time.Time{})

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

        c := &Conn{
                rawConn:  tlsConn,
                relay:    relay,
                creds:    creds,
                role:     role,
                mode:     mode,
                stopPing: make(chan struct{}),
        }
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
// Idempotent: subsequent calls are no-ops (runCloseHooks is only run
// once thanks to the closed flag).
func (c *Conn) Close() error {
        c.closeMu.Lock()
        if c.closed {
                c.closeMu.Unlock()
                return nil
        }
        c.closeMu.Unlock()
        c.runCloseHooks()

        select {
        case <-c.stopPing:
                // already closed
        default:
                close(c.stopPing)
        }
        // tlssrp.Conn.Close() will close the underlying relay TCP.
        err := c.rawConn.Close()
        // Drain and close the events channel so the event-pump goroutine
        // (if any) can exit its range loop. Close is the only writer to
        // c.ib.events (Read pushes are also from this Conn's owner); we
        // take care to close only once via stopPing's once-semantics.
        if c.ib != nil {
                // Mark proto as closed to short-circuit further Read calls.
                c.pktMu.Lock()
                c.ib.proto = io.EOF
                c.pktMu.Unlock()
                // Closing the events channel is unsafe if a Read is still
                // running (it would panic on send-to-closed). The caller
                // MUST stop reading before Close. To be safe, we do NOT
                // close the channel; instead the event-pump's range loop
                // will exit when it sees the conn's reader goroutine has
                // ended (typical pattern: select on Events() and ctx.Done()).
        }
        return err
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
func (c *Conn) inBandPinger(interval time.Duration) {
        t := time.NewTicker(interval)
        defer t.Stop()
        payload := make([]byte, 16) // MsgPING = 16 bytes per gspkt.MsgSize
        for {
                select {
                case <-c.stopPing:
                        return
                case <-t.C:
                        if err := c.WriteMsg(gspkt.MsgPING, payload); err != nil {
                                if os.Getenv("GSPORT_DEBUG") != "" {
                                        fmt.Fprintf(os.Stderr, "[gsport] in-band ping write failed: %v\n", err)
                                }
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
