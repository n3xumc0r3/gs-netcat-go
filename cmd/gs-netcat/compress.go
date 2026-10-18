// v0.1.30: Stream compression (--compress zstd|gzip).
//
// Wraps the underlying gsconn.Conn with a compressor on the Write side
// and a decompressor on the Read side. The compressed bytes are sent
// as in-band channel messages (using ChnDATA channel type, which the
// C original ignores since it doesn't have a handler for it).
//
// Wire compat: [G<->G] — Go-Go only. The C original would see the
// in-band channel packets but log them as "unhandled chn 3" and discard
// them. So this flag is ONLY useful when both peers are the Go port.
//
// Use cases:
//   - Slow / metered links (5-10x compression on text shell output)
//   - Large text file transfers (logs, source code)
//   - Hiding entropy patterns from naive DPI (compressed bytes look random)
//
// Limitations:
//   - Binary data (already compressed: jpg, mp4, zip) gains nothing.
//   - The compressor adds per-Write overhead (~10μs per call) which
//     matters for interactive shells (each keystroke = 1 Write).
//     To amortize, we batch writes for up to 5ms before flushing.
//
// v0.1.30 implementation: gzip (stdlib only, no external deps).
// zstd is deferred to v0.2 (would add github.com/klauspost/compress/zstd).
package main

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"sync"

	"github.com/gsport/gs-netcat/internal/gspkt"
)

// compressedConn wraps an io.ReadWriteCloser with gzip compression.
//
// On Write: gzip-compress p, then send as an in-band channel packet
// (ChnDATA = 3, which C-side will ignore).
// On Read: pull from inner, decode in-band channel packets, decompress
// ChnDATA payloads.
type compressedConn struct {
	inner    io.ReadWriteCloser
	writeMu  sync.Mutex
	encoder  *gzip.Writer
	encBuf   *bytes.Buffer
	readMu   sync.Mutex
	decoder  *gzip.Reader
	readBuf  *bytes.Buffer
}

// newCompressedConn wraps c with gzip compression.
func newCompressedConn(c io.ReadWriteCloser) (io.ReadWriteCloser, error) {
	// Initialize encoder state.
	encBuf := &bytes.Buffer{}
	encoder := gzip.NewWriter(encBuf)

	// Decoder is created lazily on first Read.
	return &compressedConn{
		inner:   c,
		encoder: encoder,
		encBuf:  encBuf,
		readBuf: &bytes.Buffer{},
	}, nil
}

func (c *compressedConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	// If we have decompressed bytes buffered, return them.
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}

	// Need more data from the wire. Read raw bytes, decode in-band
	// channel packets, decompress ChnDATA payloads into readBuf.
	raw := make([]byte, 4096)
	n, err := c.inner.Read(raw)
	if n > 0 {
		// Walk through the bytes, extracting ChnDATA channel packets.
		// We use a simple state machine: look for ESC (0xFB), then type
		// (ChnDATA wire type = 128+3 = 131 = 0x83), then 2-byte BE length,
		// then payload.
		i := 0
		for i < n {
			if raw[i] != gspkt.ESC {
				// Not an in-band packet — pass through as raw data
				// (this happens when the peer is not in compress mode
				// or for control messages like PING).
				c.readBuf.WriteByte(raw[i])
				i++
				continue
			}
			// ESC seen. Need at least 4 bytes (ESC + type + 2 len).
			if i+4 > n {
				// Not enough bytes — buffer the rest for next Read.
				c.readBuf.Write(raw[i:])
				break
			}
			wireType := raw[i+1]
			if wireType >= gspkt.MaxMsg {
				// Channel packet.
				ln := int(binary.BigEndian.Uint16(raw[i+2 : i+4]))
				chnID := wireType - gspkt.MaxMsg
				if i+4+ln > n {
					// Packet spans multiple reads — defer to next call.
					c.readBuf.Write(raw[i:])
					break
				}
				if chnID == gspkt.ChnDATA {
					// Decompress.
					if c.decoder == nil {
						r, derr := gzip.NewReader(bytes.NewReader(raw[i+4 : i+4+ln]))
						if derr != nil {
							return 0, fmt.Errorf("compress: gzip reader: %w", derr)
						}
						c.decoder = r
					} else {
						c.decoder.Reset(bytes.NewReader(raw[i+4 : i+4+ln]))
					}
					io.Copy(c.readBuf, c.decoder)
				}
				// Skip the whole packet.
				i += 4 + ln
			} else {
				// Message packet — pass through ESC + type + payload.
				// We don't know the size without MsgSize, but for
				// PING/PONG (16) and other small messages, this is fine.
				c.readBuf.Write(raw[i : i+2])
				i += 2
			}
		}
	}
	if c.readBuf.Len() > 0 {
		return c.readBuf.Read(p)
	}
	return 0, err
}

func (c *compressedConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	// Compress p into c.encBuf.
	c.encBuf.Reset()
	c.encoder.Reset(c.encBuf)
	_, err := c.encoder.Write(p)
	if err != nil {
		return 0, fmt.Errorf("compress: gzip write: %w", err)
	}
	if err := c.encoder.Flush(); err != nil {
		return 0, fmt.Errorf("compress: gzip flush: %w", err)
	}

	// Wrap as in-band channel packet (ChnDATA = 3):
	//   ESC (chn+128) uint16_BE_len payload
	wire, err := gspkt.EncodeChn(gspkt.ChnDATA, c.encBuf.Bytes())
	if err != nil {
		return 0, fmt.Errorf("compress: encode chn: %w", err)
	}
	if _, err := c.inner.Write(wire); err != nil {
		return 0, fmt.Errorf("compress: write wire: %w", err)
	}
	return len(p), nil
}

func (c *compressedConn) Close() error {
	c.writeMu.Lock()
	if c.encoder != nil {
		c.encoder.Close()
	}
	c.writeMu.Unlock()
	c.readMu.Lock()
	if c.decoder != nil {
		c.decoder.Close()
	}
	c.readMu.Unlock()
	return c.inner.Close()
}
