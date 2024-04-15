package xcert

import (
	"crypto/elliptic"
	"crypto/x509"
	"fmt"

	"github.com/andrewz1/xlog"

	"github.com/andrewz1/ipsec-cert/xt"
)

func (cs *certStore) loadKey() bool {
	if !xt.CheckFile(opt.Key) {
		return false
	}
	k, err := xt.LoadKeyFromFile(opt.Key)
	if err != nil {
		xlog.Warnf("load key failed: %v", err)
		return false
	}
	buf, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		xlog.Warnf("marshal key failed: %v", err)
		return false
	}
	cs.key = k
	cs.keyRaw = buf
	return true
}

func curve(bits int) elliptic.Curve {
	switch bits {
	case 224:
		return elliptic.P224()
	case 256:
		return elliptic.P256()
	case 384:
		return elliptic.P384()
	case 521:
		return elliptic.P521()
	default:
		return nil
	}
}

func (cs *certStore) genKey() error {
	var err error
	switch opt.Type {
	case "rsa":
		if opt.Bits == 0 {
			opt.Bits = 2048
		}
		cs.key, cs.keyRaw, err = xt.GenerateRSAKey(opt.Bits)
		if err != nil {
			return err
		}
	case "ecdsa":
		if opt.Bits == 0 {
			opt.Bits = 384
		}
		crv := curve(opt.Bits)
		if crv == nil {
			return fmt.Errorf("invalid key bits %d", opt.Bits)
		}
		cs.key, cs.keyRaw, err = xt.GenerateECKey(crv)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid key type: %s", opt.Type)
	}
	return xt.SaveDerToFile(cs.keyRaw, "PRIVATE KEY", opt.Key, 0600)
}

func (cs *certStore) loadOrGenKey() error {
	if cs.loadKey() {
		return nil
	}
	return cs.genKey()
}
