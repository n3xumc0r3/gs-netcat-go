package gsconn

import (
        "encoding/binary"
        "fmt"
        "os"

        "github.com/gsport/gs-netcat/internal/gspkt"
)

// inBand wraps the in-band multiplexing state attached to a Conn when
// Options.UseInBand is true. It owns a gspkt.Decoder, a buffer of
// decoded application-data bytes that have not yet been returned via
// Read, and a buffered channel of decoded in-band events.
//
// All access to inBand fields MUST be serialised by the Conn's pktMu.
// The events channel is exempt: it is safe for concurrent receive by
// the event-pump goroutine without holding pktMu.
type inBand struct {
        dec     *gspkt.Decoder
        dataBuf []byte           // decoded data bytes waiting for Read
        events  chan gspkt.Event // decoded in-band events (buffered)
        proto   error            // captured protocol error (sticky)
        // eventsClosed is set true by Conn.Close under pktMu, just before
        // closing the events channel. inBandRead (also under pktMu) checks
        // this flag before sending to avoid a panic on send-to-closed.
        eventsClosed bool
}

// newInBand constructs an inBand with a reasonably-sized event buffer.
// 256 events is enough to absorb bursts of e.g. LOG lines from a
// chatty peer without blocking the Read path; the event-pump goroutine
// is expected to drain the channel continuously.
func newInBand() *inBand {
        return &inBand{
                dec:    gspkt.NewDecoder(),
                events: make(chan gspkt.Event, 256),
        }
}

// inBandRead is the in-band-aware Read path. It is called from Conn.Read
// when c.ib != nil. It returns decoded application-data bytes from
// dataBuf, refilling dataBuf (and the events channel) from the
// underlying TLS connection as needed.
//
// On a gspkt.ErrProtocol error the error is sticky: subsequent Read
// calls return the same error without touching the wire.
//
// Events decoded during a Read are pushed into c.ib.events. If the
// event channel is full, the event is dropped (with a stderr warning if
// GSPORT_DEBUG is set) rather than blocking Read indefinitely — the
// event-pump goroutine is still expected to drain the channel.
func (c *Conn) inBandRead(p []byte) (int, error) {
        c.pktMu.Lock()
        defer c.pktMu.Unlock()

        ib := c.ib
        debug := os.Getenv("GSPORT_DEBUG") != ""
        for {
                if ib.proto != nil {
                        return 0, ib.proto
                }
                // Serve buffered data first.
                if len(ib.dataBuf) > 0 {
                        n := copy(p, ib.dataBuf)
                        ib.dataBuf = ib.dataBuf[n:]
                        return n, nil
                }
                // Need more bytes from the wire.
                raw := make([]byte, 4096)
                n, err := c.rawConn.Read(raw)
                if n > 0 {
                        out := make([]byte, n*2) // worst case: every byte is ESC, doubled
                        var events []gspkt.Event
                        _, written, derr := ib.dec.Decode(raw[:n], out, &events)
                        if derr != nil {
                                ib.proto = derr
                                return 0, fmt.Errorf("gsconn: in-band decode: %w", derr)
                        }
                        if written > 0 {
                                ib.dataBuf = append(ib.dataBuf, out[:written]...)
                        }
                        // Push events to channel. Non-blocking: drop with warning if full.
                        for _, ev := range events {
                                // Conn.Close may have closed the events channel
                                // (under pktMu, which we hold). Check the flag
                                // before sending to avoid a panic on send-to-closed.
                                if ib.eventsClosed {
                                        if debug {
                                                fmt.Fprintf(os.Stderr, "[gsport] in-band: events channel closed, dropping %+v\n", ev)
                                        }
                                        continue
                                }
                                select {
                                case ib.events <- ev:
                                default:
                                        if debug {
                                                fmt.Fprintf(os.Stderr, "[gsport] in-band: event channel full, dropping %+v\n", ev)
                                        }
                                }
                        }
                }
                if err != nil {
                        if len(ib.dataBuf) > 0 {
                                continue
                        }
                        return 0, err
                }
        }
}

// inBandWrite is the in-band-aware Write path. It escape-encodes the
// payload (doubling every 0xFB) and writes it through the underlying
// TLS connection. The returned count is len(p), not the encoded length
// — this matches io.Writer semantics.
func (c *Conn) inBandWrite(p []byte) (int, error) {
        enc := gspkt.EncodeDataAlloc(p)
        if _, err := c.rawConn.Write(enc); err != nil {
                return 0, err
        }
        return len(p), nil
}

// WriteMsg sends a fixed-length in-band message of the given type. The
// payload length MUST match gspkt.MsgSize(type) — callers are
// responsible for padding.
//
// Available in both raw and in-band modes (the wire format is the same
// and the peer's decoder will pick it up). However, in raw (cat) mode
// the peer is not running a decoder, so the message bytes would appear
// inline in the peer's data stream — typically you only call WriteMsg
// when UseInBand is true on both sides.
func (c *Conn) WriteMsg(t uint8, payload []byte) error {
        wire, err := gspkt.EncodeMsg(t, payload)
        if err != nil {
                return err
        }
        _, err = c.rawConn.Write(wire)
        return err
}

// WriteChn sends a variable-length in-band channel packet. chn is the
// channel id (0..127); the wire type byte will be chn+128.
//
// As with WriteMsg, this is wire-compatible with the peer's decoder but
// is only meaningful when both peers are in in-band mode.
func (c *Conn) WriteChn(chn uint8, payload []byte) error {
        wire, err := gspkt.EncodeChn(chn, payload)
        if err != nil {
                return err
        }
        _, err = c.rawConn.Write(wire)
        return err
}

// WriteWSIZE sends a MsgWSIZE in-band message advertising the local
// terminal's window size to the peer. The peer (if running with a PTY
// in -i mode) applies it via TIOCSWINSZ so the spawned shell's
// window-size-aware programs (vim, top, less, etc.) redraw at the
// correct dimensions.
//
// Wire format (4 bytes, big-endian): uint16 col, uint16 row — matching
// pkt_app_send_wsize in tools/pkt_mgr.c which writes htons(ws_col)
// followed by htons(ws_row).
func (c *Conn) WriteWSIZE(cols, rows uint16) error {
        var p [4]byte
        binary.BigEndian.PutUint16(p[0:2], cols)
        binary.BigEndian.PutUint16(p[2:4], rows)
        return c.WriteMsg(gspkt.MsgWSIZE, p[:])
}

// WritePWDRequest sends a MsgPWD in-band message asking the peer to
// reply with its current working directory via a ChnPWD channel packet.
// Matches pkt_app_send_pwdrequest in tools/pkt_mgr.c.
func (c *Conn) WritePWDRequest() error {
        // MsgPWD payload is 4 bytes per MsgSize(3 == 4).
        return c.WriteMsg(gspkt.MsgPWD, make([]byte, 4))
}

// WritePWDReply sends a ChnPWD channel packet containing wd (NUL-
// terminated). Called on the server side in response to a MsgPWD
// request. Matches pkt_app_send_pwdreply in tools/pkt_mgr.c.
func (c *Conn) WritePWDReply(wd string) error {
        // +1 for the NUL terminator that the C original appends.
        payload := make([]byte, len(wd)+1)
        copy(payload, wd)
        return c.WriteChn(gspkt.ChnPWD, payload)
}

// Events returns the channel of decoded in-band events. The event-pump
// goroutine MUST range over this channel for as long as the Conn is
// open; otherwise events may be dropped (the channel is buffered to
// 256, and Read drops new events if the channel fills).
//
// Returns nil if the Conn is not in in-band mode.
func (c *Conn) Events() <-chan gspkt.Event {
        if c.ib == nil {
                return nil
        }
        return c.ib.events
}

// InBand reports whether the Conn is running in in-band multiplexing
// mode (Options.UseInBand was true at Dial time).
func (c *Conn) InBand() bool { return c.ib != nil }

// PollEvent returns the next pending in-band event without blocking.
// ok is false if no event is pending or if the Conn is not in in-band
// mode. This is a non-blocking convenience wrapper around the Events()
// channel.
func (c *Conn) PollEvent() (ev gspkt.Event, ok bool) {
        if c.ib == nil {
                return gspkt.Event{}, false
        }
        select {
        case ev = <-c.ib.events:
                return ev, true
        default:
                return gspkt.Event{}, false
        }
}
