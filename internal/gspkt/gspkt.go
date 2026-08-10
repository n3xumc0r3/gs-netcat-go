// Package gspkt implements the in-band multiplexing protocol used by
// gs-netcat (lib/packet.c in the C original) to run fixed-length
// signalling messages and variable-length channel streams over the
// same TLS-SRP-secured byte stream.
//
// # Wire format
//
// All bytes are sent over the TLS channel as a single byte stream. The
// escape byte GS_PKT_ESC (0xFB) marks the start of an in-band packet.
// To send a literal 0xFB as application data, the encoder emits ESC ESC
// (0xFB 0xFB); the decoder collapses that back to a single 0xFB.
//
//	Message (fixed length, type 1..127):
//	    ESC type [payload of size MsgSize(type)]
//
//	Channel (variable length, type 128..255; chn id = type - 128):
//	    ESC type [uint16 len BE] [len bytes payload]
//
//	type == 0 is a protocol error (FATAL).
//
// # Use
//
// The Encoder is stateless (write data → bytes to put on the wire). The
// Decoder is stateful: feed it bytes via Decode and it returns the
// decoded application-data bytes plus a slice of in-band Events (one
// per completed message/channel) that arrived in this chunk. A single
// in-band packet may be split across multiple Decode calls.
//
// The protocol is byte-for-byte compatible with THC gs-netcat v1.4.42
// (lib/packet.c).
package gspkt

import (
	"encoding/binary"
	"errors"
)

// ESC is the in-band escape byte (0xFB). To send a literal 0xFB as
// application data, the encoder emits ESC ESC.
const ESC byte = 0xFB

// Maximum sizes / constants matching packet.h.
const (
	MaxSize   = 2048 // max payload of a single packet (excl. header)
	HdrMaxLen = 4    // max header length (ESC + type + 2-byte length)
	MaxMsg    = 128  // type 0..127 = message
	MaxChn    = 128  // type 128..255 = channel (id = type - 128)

	MsgHdrLen = 2 // ESC + type
	ChnHdrLen = 4 // ESC + type + uint16 len
)

// Message type constants used by gs-netcat (tools/pkt_mgr.h).
//
// The number itself dictates the message size (see MsgSize): messages
// 1..15 are 4 bytes, 16..31 are 16 bytes, 32..47 are 64 bytes, ...
const (
	MsgNone   uint8 = 0  // FATAL protocol error if seen on the wire
	MsgWSIZE  uint8 = 1  // 4 bytes: terminal window size change (col, row, BE)
	MsgIDS    uint8 = 2  // 4 bytes: client wants IDS log messages
	MsgPWD    uint8 = 3  // 4 bytes: client requests server's working directory
	MsgPING   uint8 = 16 // 16 bytes: app-level ping (struct _pkt_app_ping)
	MsgPONG   uint8 = 16 // 16 bytes: app-level pong (struct _pkt_app_pong)
	MsgLOG    uint8 = 32 // 64 bytes: log line (type + msg[63])
	MsgSTATUS uint8 = 33 // 64 bytes: status (type + msg[63])
)

// Channel type constants (tools/pkt_mgr.h).  These are the values the
// caller passes to WriteChn / that arrive in Event.Chn. The wire byte
// is type+128.
const (
	ChnPUT         uint8 = 0 // file transfer: PUT
	ChnACCEPT      uint8 = 1 // file transfer: ACCEPT
	ChnLISTREQUEST uint8 = 2 // file transfer: LIST_REQUEST
	ChnDATA        uint8 = 3 // file transfer: DATA
	ChnERROR       uint8 = 4 // file transfer: ERROR
	ChnSWITCH      uint8 = 5 // file transfer: SWITCH
	ChnLISTREPLY   uint8 = 6 // file transfer: LIST_REPLY
	ChnDL          uint8 = 7 // file transfer: DL
	ChnPWD         uint8 = 8 // server → client: working-directory reply (NUL-terminated)
)

// MsgSize returns the fixed payload size of a message of the given type
// (matching GS_PKT_MSG_size_by_type in lib/packet.c).
//
//	type 0       → -2  (FATAL protocol error)
//	type 1..15   → 4
//	type 16..31  → 16
//	type 32..47  → 64
//	type 48..63  → 128
//	type 64..79  → 512
//	type 80..95  → 1024
//	type 96..111 → 2048
//	type 112..127 → 4196  (sic! not 4096 — matches the C original)
func MsgSize(t int) int {
	switch {
	case t == 0:
		return -2 // protocol error (FATAL)
	case t < 16:
		return 4
	case t < 32:
		return 16
	case t < 48:
		return 64
	case t < 64:
		return 128
	case t < 80:
		return 512
	case t < 96:
		return 1024
	case t < 112:
		return 2048
	default: // t < 128
		return 4196
	}
}

// ErrProtocol is returned by Decoder.Decode when the input stream
// contains an in-band protocol error (type 0, or any impossible state).
// The caller MUST close the connection — recovery is not possible.
var ErrProtocol = errors.New("gspkt: in-band protocol error")

// EventKind classifies a decoded in-band event.
type EventKind int

const (
	EventMessage EventKind = iota // fixed-length message (type 0..127)
	EventChannel                  // variable-length channel (type 128..255)
)

// Event is a single decoded in-band event. For EventMessage, Type is
// the raw wire type (1..127). For EventChannel, Type is the channel id
// (0..127) — i.e. wire_type - 128 — matching how the C original passes
// the value to the callback (pkt->type - GS_PKT_MAX_MSG).
type Event struct {
	Kind EventKind
	Type uint8  // for Msg: 1..127; for Chn: 0..127
	Data []byte // payload (may be empty for zero-length channels)
	Raw  uint8  // raw wire type (always 1..255; 0 would be ErrProtocol)
}

// EncodeData writes src into dst, doubling every 0xFB. dst must have
// capacity at least 2*len(src). Returns the number of bytes written.
//
// This mirrors GS_PKT_encode in lib/packet.c. It is used to wrap
// application data before sending it over the in-band-aware channel so
// that a literal 0xFB in the data cannot be mistaken for the start of
// an in-band packet.
func EncodeData(src []byte, dst []byte) int {
	if len(src) == 0 {
		return 0
	}
	// Allocate-or-bounds-check is the caller's responsibility; we
	// trust the contract (dst cap >= 2*len(src)) here.
	n := 0
	for _, b := range src {
		dst[n] = b
		n++
		if b == ESC {
			dst[n] = ESC
			n++
		}
	}
	return n
}

// EncodeDataAlloc is a convenience wrapper that allocates the result.
func EncodeDataAlloc(src []byte) []byte {
	out := make([]byte, 0, len(src)+8)
	for _, b := range src {
		out = append(out, b)
		if b == ESC {
			out = append(out, ESC)
		}
	}
	return out
}

// EncodeMsg returns the wire bytes for a fixed-length message of the
// given type. The payload length must exactly match MsgSize(type); the
// caller is responsible for padding to the correct size.
//
// Wire form: ESC type [payload...]
// ESC bytes inside the payload are NOT escaped (the C original does not
// escape them either — see pkt_app_send_* in tools/pkt_mgr.c which
// writes the raw payload after the type byte).
func EncodeMsg(t uint8, payload []byte) ([]byte, error) {
	want := MsgSize(int(t))
	if want < 0 {
		return nil, ErrProtocol
	}
	if len(payload) != want {
		return nil, ErrProtocol
	}
	out := make([]byte, 0, MsgHdrLen+want)
	out = append(out, ESC, t)
	out = append(out, payload...)
	return out, nil
}

// EncodeChn returns the wire bytes for a variable-length channel
// packet. chn is the channel id (0..127); the wire type byte will be
// chn + 128.
//
// Wire form: ESC (chn+128) [uint16 len BE] [payload...]
// ESC bytes inside the payload are NOT escaped (the C original does not
// escape them either — see pkt_app_send_pwdreply in tools/pkt_mgr.c).
func EncodeChn(chn uint8, payload []byte) ([]byte, error) {
	if chn >= MaxChn {
		return nil, ErrProtocol
	}
	if len(payload) > 0xFFFF {
		return nil, ErrProtocol
	}
	out := make([]byte, 0, ChnHdrLen+len(payload))
	out = append(out, ESC, chn+MaxMsg)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(payload)))
	out = append(out, lenBuf[:]...)
	out = append(out, payload...)
	return out, nil
}

// decoder state machine values. Mirrors the esc_len_rem / type / len /
// is_got_chn_len fields of GS_PKT in packet.h.
type decState int

const (
	stNormal   decState = iota // looking for either data or ESC
	stAfterEsc                 // saw ESC, deciding what kind of packet
	stInMsg                    // inside message payload (knows escLen)
	stInChnLen                 // inside channel length (2 bytes)
	stInChn                    // inside channel payload (knows escLen)
)

// Decoder is the stateful in-band decoder. Feed it bytes via Decode;
// it returns the application-data bytes (with ESC ESC collapsed to ESC)
// plus any in-band Events that completed within the call.
//
// A single in-band packet may be split across multiple Decode calls;
// the decoder buffers only the in-band payload being assembled (≤4196
// bytes per message), never the entire input.
type Decoder struct {
	state     decState
	curType   uint8  // raw wire type of in-flight packet
	escLen    int    // bytes remaining until in-flight payload completes
	gotChnLen bool   // for channel: have we read the 2-byte length yet?
	inband    []byte // accumulating payload for current in-band packet
}

// NewDecoder returns a fresh Decoder.
func NewDecoder() *Decoder { return &Decoder{} }

// Reset clears all internal state (useful for reconnect scenarios).
func (d *Decoder) Reset() {
	d.state = stNormal
	d.curType = 0
	d.escLen = 0
	d.gotChnLen = false
	if d.inband != nil {
		d.inband = d.inband[:0]
	}
}

// Decode consumes up to len(src) bytes from src, writing the decoded
// application-data bytes into dst and appending any completed in-band
// events to *out. Returns the number of bytes consumed from src and the
// number of application-data bytes written to dst.
//
// dst must have capacity at least len(src). If dst is too small the
// function still consumes as many src bytes as fit and returns the
// count; the caller is expected to call again with the remainder.
//
// On ErrProtocol the caller MUST close the connection; further Decode
// calls on the same Decoder will return the same error.
func (d *Decoder) Decode(src, dst []byte, out *[]Event) (consumed, written int, err error) {
	i, j := 0, 0
	for i < len(src) {
		b := src[i]

		switch d.state {
		case stNormal:
			if b == ESC {
				d.state = stAfterEsc
				d.curType = 0
				d.escLen = 1 // "after ESC, expecting 1 byte to tell us what kind"
				i++
				continue
			}
			dst[j] = b
			j++
			i++

		case stAfterEsc:
			// First byte after ESC decides packet kind.
			if b == ESC {
				// ESC ESC => literal ESC in data stream
				dst[j] = ESC
				j++
				d.state = stNormal
				d.escLen = 0
				i++
				continue
			}
			// b is the type byte. Type 0 = FATAL.
			if b == 0 {
				return i, j, ErrProtocol
			}
			d.curType = b
			if d.inband != nil {
				d.inband = d.inband[:0]
			}
			if b >= MaxMsg {
				// Channel: 2-byte length follows.
				d.state = stInChnLen
				d.escLen = 2
				d.gotChnLen = false
			} else {
				want := MsgSize(int(b))
				if want < 0 {
					return i, j, ErrProtocol
				}
				d.state = stInMsg
				d.escLen = want
			}
			i++

		case stInMsg, stInChnLen, stInChn:
			// Copy as many bytes as we can into inband.
			need := d.escLen
			avail := len(src) - i
			take := need
			if avail < take {
				take = avail
			}
			d.inband = append(d.inband, src[i:i+take]...)
			d.escLen -= take
			i += take

			if d.escLen > 0 {
				// still need more bytes
				continue
			}

			// Completed a sub-phase.
			if d.state == stInChnLen && !d.gotChnLen {
				// Just finished the 2-byte length prefix.
				ln := int(binary.BigEndian.Uint16(d.inband))
				d.inband = d.inband[:0]
				d.gotChnLen = true
				if ln == 0 {
					// Zero-length channel packet — still emit event.
					*out = append(*out, Event{
						Kind: EventChannel,
						Type: d.curType - MaxMsg,
						Data: nil,
						Raw:  d.curType,
					})
					d.state = stNormal
					d.curType = 0
					d.gotChnLen = false
					continue
				}
				d.state = stInChn
				d.escLen = ln
				continue
			}

			// Completed payload (msg or chn).
			if d.state == stInMsg {
				*out = append(*out, Event{
					Kind: EventMessage,
					Type: d.curType,
					Data: append([]byte(nil), d.inband...),
					Raw:  d.curType,
				})
			} else { // stInChn
				*out = append(*out, Event{
					Kind: EventChannel,
					Type: d.curType - MaxMsg,
					Data: append([]byte(nil), d.inband...),
					Raw:  d.curType,
				})
			}
			d.state = stNormal
			d.curType = 0
			d.gotChnLen = false
			d.inband = d.inband[:0]
		}
	}
	return i, j, nil
}
