// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tlssrp

import (
        "crypto/hmac"
        "crypto/sha512"
        "io"
        "math/big"
)

type srpKeyAgreement struct {
        N, g  *big.Int
        a, A  *big.Int
        b, B  *big.Int
        v     *big.Int
        pms   []byte
        valid bool // used to fake the authentication process, hiding fact that user doesn't exist
}

func (ka *srpKeyAgreement) generateServerKeyExchange(config *Config, clientHello *clientHelloMsg, hello *serverHelloMsg) (*serverKeyExchangeMsg, error) {
        if clientHello.srpUser == nil {
                return nil, alert(alertUnknownPskIdentity)
        }

        vbuf, s, grp, err := config.SRPLookup.Lookup(string(clientHello.srpUser))
        if err != nil {
                return nil, err
        }

        // we always calculate a salt & verifier, for the cases where users don't exist.
        // this ensures attackers cannot deduct from error messages if a user exists or not.
        // see http://tools.ietf.org/html/rfc5054#section-2.5.1, at 2.5.1.3 Unknown SRP
        h := hmac.New(sha512.New, []byte(config.SRPSaltKey))
        h.Write([]byte("salt"))
        h.Write(clientHello.srpUser)
        sfake := h.Sum(nil)[:config.SRPSaltSize]

        ka.valid = true
        vfake := SRPVerifier(string(clientHello.srpUser), "password", sfake, grp)
        if vbuf == nil || s == nil {
                vbuf, s = vfake, sfake
                ka.valid = false
        }

        // rfc suggests "at least 256 bits, for 128-bits security"
        bbuf := make([]byte, 512/8)
        _, err = io.ReadFull(config.rand(), bbuf)
        if err != nil {
                return nil, err
        }

        ka.N = grp.N
        ka.g = grp.G
        ka.v = bigint(vbuf)

        ka.b = new(big.Int).SetBytes(bbuf)
        ka.B = srpB(ka.N, ka.g, ka.v, ka.b)

        msg := new(serverKeyExchangeMsg)
        msg.N = ka.N.Bytes()
        msg.g = ka.g.Bytes()
        msg.s = s
        msg.B = ka.B.Bytes()

        return msg, nil
}

func (ka *srpKeyAgreement) processClientKeyExchange(config *Config, ckx *clientKeyExchangeMsg, version uint16) ([]byte, error) {
        ka.A = new(big.Int).SetBytes(ckx.A)

        if new(big.Int).Rem(ka.A, ka.N).Sign() == 0 {
                return nil, alert(alertIllegalParameter)
        }

        // always create the fake pms
        // v0.1.29 (audit-3 LOW): size fakepms to match the real PMS length.
        // For SRP-4096 the real PMS is up to 512 bytes; HMAC-SHA256 hashes
        // keys > 64 bytes (8 extra SHA-256 blocks for 512 bytes). A fixed
        // 16-byte fakepms would create a ~800ns timing side-channel between
        // "user exists" and "user doesn't exist" paths. Now both paths use
        // the same PMS length.
        fakepmsLen := len(ka.N.Bytes())
        if fakepmsLen < 16 {
                fakepmsLen = 16 // defensive floor
        }
        fakepms := make([]byte, fakepmsLen)
        _, err := io.ReadFull(config.rand(), fakepms)
        if err != nil {
                return nil, err
        }

        pmsBig, err := srpServerPms(ka.N, ka.g, ka.A, ka.B, ka.b, ka.v)
        if err != nil {
                return nil, err
        }
        pms := pmsBig.Bytes()
        if !ka.valid {
                pms = fakepms
        }
        return pms, nil
}

func (ka *srpKeyAgreement) serverValidExchange() bool {
        return ka.valid
}

func (ka *srpKeyAgreement) processServerKeyExchange(config *Config, clientHello *clientHelloMsg, serverHello *serverHelloMsg, skx *serverKeyExchangeMsg) error {
        ka.N = new(big.Int).SetBytes(skx.N)
        ka.g = new(big.Int).SetBytes(skx.g)
        s := skx.s
        ka.B = new(big.Int).SetBytes(skx.B)

        // v0.1.29 (audit-3 LOW): validate group FIRST, then check B mod N.
        // Previously B mod N was checked first using unvalidated N — a
        // malicious server sending N=1 would make Rem(B, 1) == 0 and
        // return alertIllegalParameter instead of alertInsufficientSecurity
        // (wrong alert for invalid group). Worse, N=0 could panic in Rem
        // before group validation. Per RFC 5054 the group is validated
        // first, then B is checked.
        if !srpValidGroup(config, ka.N, ka.g) {
                return alert(alertInsufficientSecurity)
        }

        if new(big.Int).Rem(ka.B, ka.N).Sign() == 0 {
                return alert(alertIllegalParameter)
        }

        // rfc suggests "at least 256 bits, for 128-bits security"
        abuf := make([]byte, 512/8)
        _, err := io.ReadFull(config.rand(), abuf)
        if err != nil {
                return err
        }
        ka.a = new(big.Int).SetBytes(abuf)

        A, pms := srpClientPms(config.SRPUser, config.SRPPassword, ka.N, ka.g, ka.a, ka.B, s)
        ka.A = A
        ka.pms = pms.Bytes()
        return nil
}

func (ka *srpKeyAgreement) generateClientKeyExchange(config *Config, clientHello *clientHelloMsg) ([]byte, *clientKeyExchangeMsg, error) {
        ckx := new(clientKeyExchangeMsg)
        ckx.A = ka.A.Bytes()
        return ka.pms, ckx, nil
}
