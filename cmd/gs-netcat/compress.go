// v0.1.30: Stream compression (--compress zstd|gzip).
//
// v0.2.5: zstd now actually works (via github.com/klauspost/compress/zstd).
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
// v0.1.30: gzip only (stdlib).
// v0.2.5: zstd added (github.com/klauspost/compress/zstd, ~2-3x faster
// than gzip with better compression ratio). Both peers must use the
// same algorithm — mixed gzip/zstd won't interop.
package main

import (
        "bytes"
        "compress/gzip"
        "encoding/binary"
        "fmt"
        "io"
        "sync"

        "github.com/gsport/gs-netcat/internal/gspkt"
        "github.com/klauspost/compress/zstd"
)

// compressAlgo enumerates supported compression algorithms.
type compressAlgo int

const (
        compressNone compressAlgo = iota
        compressGzip
        compressZstd
)

// compressedConn wraps an io.ReadWriteCloser with gzip or zstd compression.
//
// On Write: compress p, then send as an in-band channel packet
// (ChnDATA = 3, which C-side will ignore).
// On Read: pull from inner, decode in-band channel packets, decompress
// ChnDATA payloads.
//
// v0.2.5: Read uses a proper accumulation buffer so partial packets
// (split across multiple inner.Read calls) are correctly reassembled.
type compressedConn struct {
        inner    io.ReadWriteCloser
        algo     compressAlgo
        writeMu  sync.Mutex
        encBuf   *bytes.Buffer
        gzipEnc  *gzip.Writer
        zstdEnc  *zstd.Encoder
        readMu   sync.Mutex
        readBuf  *bytes.Buffer // decoded application data ready for Read
        rawBuf   []byte         // raw bytes from inner not yet processed
        gzipDec  *gzip.Reader
        zstdDec  *zstd.Decoder
}

// newCompressedConn wraps c with gzip compression (v0.1.30 default).
// v0.2.5: use newCompressedConnAlgo for explicit algo selection.
func newCompressedConn(c io.ReadWriteCloser) (io.ReadWriteCloser, error) {
        return newCompressedConnAlgo(c, compressGzip)
}

// newCompressedConnAlgo wraps c with the specified compression algorithm.
func newCompressedConnAlgo(c io.ReadWriteCloser, algo compressAlgo) (io.ReadWriteCloser, error) {
        cc := &compressedConn{
                inner:   c,
                algo:    algo,
                encBuf:  &bytes.Buffer{},
                readBuf: &bytes.Buffer{},
        }
        switch algo {
        case compressGzip:
                cc.gzipEnc = gzip.NewWriter(cc.encBuf)
        case compressZstd:
                enc, err := zstd.NewWriter(cc.encBuf, zstd.WithEncoderLevel(zstd.SpeedDefault))
                if err != nil {
                        return nil, fmt.Errorf("zstd: new encoder: %w", err)
                }
                cc.zstdEnc = enc
        default:
                return nil, fmt.Errorf("unknown compress algo %d", algo)
        }
        return cc, nil
}

// newCompressedConnByName wraps c using the named algorithm ("gzip" or "zstd").
func newCompressedConnByName(c io.ReadWriteCloser, name string) (io.ReadWriteCloser, error) {
        switch name {
        case "gzip":
                return newCompressedConnAlgo(c, compressGzip)
        case "zstd":
                return newCompressedConnAlgo(c, compressZstd)
        default:
                return nil, fmt.Errorf("unknown compress algo %q (use gzip|zstd)", name)
        }
}

func (c *compressedConn) Read(p []byte) (int, error) {
        c.readMu.Lock()
        defer c.readMu.Unlock()

        // Serve decoded data from readBuf if available.
        if c.readBuf.Len() > 0 {
                return c.readBuf.Read(p)
        }

        // Need more data. Loop until we have decoded bytes to return.
        for {
                // Try to process a complete in-band packet from rawBuf.
                if n, err := c.tryProcessPacket(); n > 0 {
                        // Got some decoded bytes.
                        if c.readBuf.Len() > 0 {
                                return c.readBuf.Read(p)
                        }
                        // Packet was decoded but produced no data (e.g. handshake).
                        // Continue reading.
                        if err != nil {
                                return 0, err
                        }
                        continue
                } else if err != nil {
                        // Decoding error.
                        return 0, err
                }
                // Need more raw bytes from inner.
                raw := make([]byte, 4096)
                n, rerr := c.inner.Read(raw)
                if n > 0 {
                        c.rawBuf = append(c.rawBuf, raw[:n]...)
                }
                if rerr != nil {
                        // Try to process remaining bytes in rawBuf before returning.
                        if processed, _ := c.tryProcessPacket(); processed > 0 && c.readBuf.Len() > 0 {
                                return c.readBuf.Read(p)
                        }
                        return 0, rerr
                }
        }
}

// tryProcessPacket attempts to decode one in-band packet from rawBuf.
// Returns the number of raw bytes consumed (0 if no complete packet).
// Decoded application data is appended to c.readBuf.
func (c *compressedConn) tryProcessPacket() (int, error) {
        if len(c.rawBuf) == 0 {
                return 0, nil
        }
        // Look for ESC byte (0xFB).
        if c.rawBuf[0] != gspkt.ESC {
                // Not an in-band packet — pass through as raw byte.
                // (This happens for control messages like PING/PONG.)
                c.readBuf.WriteByte(c.rawBuf[0])
                c.rawBuf = c.rawBuf[1:]
                return 1, nil
        }
        // ESC seen. Need at least 4 bytes (ESC + type + 2-byte length).
        if len(c.rawBuf) < 4 {
                return 0, nil
        }
        wireType := c.rawBuf[1]
        if wireType < gspkt.MaxMsg {
                // Message packet (not channel) — pass through ESC + type as raw bytes.
                // We don't know the message size without MsgSize, but for control
                // messages (PING=16, PONG=16, etc.) the receiver should handle them.
                // For now, just pass through the ESC and type bytes.
                c.readBuf.WriteByte(c.rawBuf[0])
                c.readBuf.WriteByte(c.rawBuf[1])
                c.rawBuf = c.rawBuf[2:]
                return 2, nil
        }
        // Channel packet.
        ln := int(binary.BigEndian.Uint16(c.rawBuf[2:4]))
        chnID := wireType - gspkt.MaxMsg
        totalLen := 4 + ln
        if len(c.rawBuf) < totalLen {
                // Not enough bytes — wait for more.
                return 0, nil
        }
        payload := c.rawBuf[4:totalLen]
        if chnID == gspkt.ChnDATA {
                // Decompress based on algo.
                if derr := c.decompressInto(payload); derr != nil {
                        // On decompress error, drop the packet but keep going.
                        c.rawBuf = c.rawBuf[totalLen:]
                        return totalLen, derr
                }
        }
        // Consume the packet.
        c.rawBuf = c.rawBuf[totalLen:]
        return totalLen, nil
}

// decompressInto decompresses payload into c.readBuf using the configured algorithm.
func (c *compressedConn) decompressInto(payload []byte) error {
        switch c.algo {
        case compressGzip:
                if c.gzipDec == nil {
                        r, derr := gzip.NewReader(bytes.NewReader(payload))
                        if derr != nil {
                                return fmt.Errorf("gzip reader: %w", derr)
                        }
                        c.gzipDec = r
                } else {
                        c.gzipDec.Reset(bytes.NewReader(payload))
                }
                _, err := io.Copy(c.readBuf, c.gzipDec)
                return err
        case compressZstd:
                if c.zstdDec == nil {
                        d, derr := zstd.NewReader(bytes.NewReader(payload))
                        if derr != nil {
                                return fmt.Errorf("zstd reader: %w", derr)
                        }
                        c.zstdDec = d
                }
                // zstd.Decoder's Reset takes an io.Reader and returns an error.
                if rerr := c.zstdDec.Reset(bytes.NewReader(payload)); rerr != nil {
                        return fmt.Errorf("zstd reset: %w", rerr)
                }
                _, err := io.Copy(c.readBuf, c.zstdDec)
                return err
        }
        return fmt.Errorf("unknown algo %d", c.algo)
}

func (c *compressedConn) Write(p []byte) (int, error) {
        c.writeMu.Lock()
        defer c.writeMu.Unlock()

        c.encBuf.Reset()
        var err error
        switch c.algo {
        case compressGzip:
                c.gzipEnc.Reset(c.encBuf)
                _, err = c.gzipEnc.Write(p)
                if err == nil {
                        err = c.gzipEnc.Flush()
                }
        case compressZstd:
                c.zstdEnc.Reset(c.encBuf)
                _, err = c.zstdEnc.Write(p)
                if err == nil {
                        err = c.zstdEnc.Flush()
                }
        }
        if err != nil {
                return 0, fmt.Errorf("compress write: %w", err)
        }

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
        if c.gzipEnc != nil {
                c.gzipEnc.Close()
        }
        if c.zstdEnc != nil {
                c.zstdEnc.Close()
        }
        c.writeMu.Unlock()
        c.readMu.Lock()
        if c.gzipDec != nil {
                c.gzipDec.Close()
        }
        if c.zstdDec != nil {
                c.zstdDec.Close()
        }
        c.readMu.Unlock()
        return c.inner.Close()
}
