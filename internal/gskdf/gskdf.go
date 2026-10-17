// Package gskdf implements the gs-netcat secret-derivation functions.
//
// gs-netcat (gsocket) derives all cryptographic material from a single
// user-supplied "gs_secret" string.  The relay never sees the secret; it
// only routes by the derived 128-bit GS-Address.  The two peers must
// exchange the secret out-of-band; once both sides have it, each can
// independently derive:
//
//   - gs_address:   SHA256("/kd/addr/2" || secret)[0:16]   — relay routing key
//   - srp_password: "Blah." || hex(SHA256("/kd/srp/1" || secret))[0:33] || ".blubb-SRPSEC"
//                                                              — TLS-SRP password
//
// The "Blah." + ".blubb-SRPSEC" wrapping is what the C implementation
// (lib/gsocket-ssl.c:GS_srp_setpassword) feeds to OpenSSL.  Reproducing
// it byte-for-byte is REQUIRED for wire compatibility.
//
// The username passed to TLS-SRP is the literal string "user".
//
// References:
//   - gsocket v1.4.42 lib/gsocket-util.c:GS_ADDR_sec2addr
//   - gsocket v1.4.42 lib/gsocket-ssl.c:GS_srp_setpassword
//   - /home/z/my-project/research/gs-netcat-analysis.md §3, §5.1
package gskdf

import (
        "crypto/rand"
        "crypto/sha256"
        "encoding/hex"
        "fmt"
)

// SaltLength is the salt length used by OpenSSL's SRP_create_verifier_BN.
// A5 wire-capture empirically confirmed this is 20 bytes (NOT 16, as the
// original A4 analysis assumed).  Verified by:
//   - direct call to SRP_create_verifier_BN in /home/z/my-project/scripts/srp_capture.c
//   - wire capture of ServerKeyExchange: salt-length field = 0x14 = 20
//   - `openssl srp -add` command output
const SaltLength = 20

// SRPUsername is the literal TLS-SRP username the C implementation hardcodes.
// See lib/gsocket-ssl.c:31,87,153.
const SRPUsername = "user"

// SRPWrappingPrefix and SRPWrappingSuffix together form the deterministic
// 13-byte wrapping applied to the derived SRP password.  Together with the
// 33-hex-char inner password this yields a 51-char string fed to OpenSSL's
// SRP_create_verifier_BN.  See lib/gsocket-ssl.c:513-518 (GS_srp_setpassword).
const (
        SRPWrappingPrefix = "Blah."
        SRPWrappingSuffix = ".blubb-SRPSEC"
)

// AddrLen is the length of a GS-Address in bytes (always 16, per gsocket.h).
const AddrLen = 16

// Addr is a 128-bit GS-Address.  It is the routing key the GSRN relay
// uses to match a _gs_listen with a _gs_connect.
type Addr [AddrLen]byte

// Bytes returns a slice copy of the address.
func (a Addr) Bytes() []byte { out := make([]byte, AddrLen); copy(out, a[:]); return out }

// String returns the lowercase-hex representation, matching what
// gs-netcat prints with `GS_addr2hex`.
func (a Addr) String() string { return hex.EncodeToString(a[:]) }

// Credentials bundles all values derived from a single gs_secret.
//
// Field order matches the C implementation's mental model:
//   1. Secret is the user input.
//   2. Address is the relay routing key (only value the relay sees).
//   3. SRPUsername + SRPPassword are the TLS-SRP credentials both peers
//      use to authenticate the in-pipe TLS handshake.
type Credentials struct {
        // Secret is the user-supplied gs_secret, untouched.  Kept here so
        // callers can echo it back to the user / log it on -v.
        Secret string

        // Address is the 16-byte GS-Address.
        Address Addr

        // SRPUsername is always "user" (see lib/gsocket-ssl.c).
        SRPUsername string

        // SRPPassword is the 51-char wrapped password fed to TLS-SRP:
        //   "Blah." + hex(SHA256("/kd/srp/1" || secret))[0:33] + ".blubb-SRPSEC"
        SRPPassword string
}

// Derive computes all derived values from a single gs_secret string.
//
// The derivation is intentionally identical to the C implementation so
// that a Go peer and a C peer with the same secret end up with the same
// GS-Address (so the relay can match them) and the same SRP password
// (so the TLS-SRP handshake succeeds).  See analysis §3 and §5.1.
func Derive(secret string) *Credentials {
        // gs_address = SHA256("/kd/addr/2" || secret)[0:16]
        addrHash := sha256.New()
        addrHash.Write([]byte("/kd/addr/2"))
        addrHash.Write([]byte(secret))
        var addr Addr
        copy(addr[:], addrHash.Sum(nil)[:AddrLen])

        // srp_inner = hex(SHA256("/kd/srp/1" || secret))[0:33]
        srpHash := sha256.New()
        srpHash.Write([]byte("/kd/srp/1"))
        srpHash.Write([]byte(secret))
        srpInner := hex.EncodeToString(srpHash.Sum(nil))[:33]

        // srp_password = "Blah." + srp_inner + ".blubb-SRPSEC"  (51 chars total)
        srpPassword := SRPWrappingPrefix + srpInner + SRPWrappingSuffix

        return &Credentials{
                Secret:      secret,
                Address:     addr,
                SRPUsername: SRPUsername,
                SRPPassword: srpPassword,
        }
}

// GenSecret generates a fresh 21-char base58 secret, matching the format
// that `gs-netcat -g` prints and that GS_gen_secret produces in
// lib/gsocket-util.c:152-170.
//
// Implementation note: the C version draws 32 random bytes and base58-encodes
// the result, truncating to 21 chars.  We do the same here.  The exact byte
// count does not matter as long as we have enough entropy for 21 chars of
// base58 (which needs ~123 bits = ~16 bytes); we draw 32 for parity.
func GenSecret() (string, error) {
        const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        const targetLen = 21

        buf := make([]byte, 32)
        if _, err := rand.Read(buf); err != nil {
                return "", fmt.Errorf("gskdf: rand: %w", err)
        }

        // Treat buf as a big-endian unsigned integer, repeatedly divmod by 58.
        // This is the standard base58 encoding (no checksum, unlike Bitcoin's
        // base58check).
        // v0.1.28 (audit-4 bug #10, LOW): handle leading zero bytes.
        // Standard base58 (Bitcoin BIP) maps each leading 0x00 byte to
        // a '1' prefix. The previous code skipped leading zero bytes
        // entirely (because `acc < 58 && !started`), so secrets with
        // a leading 0x00 byte in the random buffer (≈0.4% of secrets)
        // were shorter than targetLen and diverged from C gs-netcat's
        // base58 output. Now we emit one '1' per leading zero byte,
        // matching Bitcoin/C convention.
        leadingZeros := 0
        for leadingZeros < len(buf) && buf[leadingZeros] == 0 {
                leadingZeros++
        }
        num := make([]byte, len(buf))
        copy(num, buf)
        out := make([]byte, 0, targetLen+4)
        // Emit one base58 '1' per leading zero byte (matches Bitcoin/C).
        for i := 0; i < leadingZeros; i++ {
                out = append(out, alphabet[0]) // alphabet[0] == '1'
        }
        for {
                // Divide num by 58, remainder in acc.
                var acc int
                var newNum []byte
                started := false
                for _, b := range num {
                        acc = acc*256 + int(b)
                        if acc >= 58 || started {
                                newNum = append(newNum, byte(acc/58))
                                acc = acc % 58
                                started = true
                        }
                }
                out = append(out, alphabet[acc])
                num = newNum
                if len(num) == 0 {
                        break
                }
        }
        // Reverse out.
        for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
                out[i], out[j] = out[j], out[i]
        }
        if len(out) > targetLen {
                out = out[:targetLen]
        }
        return string(out), nil
}

// DeriveAuthToken produces a 16-byte deterministic auth-token from a
// user-supplied token string, mirroring GS_set_token's `-a` flag path
// (lib/gsocket-engine.c:2311-2328):
//
//      token = SHA256(token_str || gs_addr)[0:16]
//
// If tokenStr is empty the caller should instead generate a random 16-byte
// token (see GenRandomToken).
func DeriveAuthToken(tokenStr string, addr Addr) [16]byte {
        h := sha256.New()
        h.Write([]byte(tokenStr))
        h.Write(addr[:])
        var out [16]byte
        copy(out[:], h.Sum(nil)[:16])
        return out
}

// GenRandomToken returns 16 cryptographically random bytes, mirroring
// the default behaviour of GS_set_token(gs, NULL, 0) when no `-a` is passed.
func GenRandomToken() ([16]byte, error) {
        var t [16]byte
        if _, err := rand.Read(t[:]); err != nil {
                return t, fmt.Errorf("gskdf: rand: %w", err)
        }
        return t, nil
}
