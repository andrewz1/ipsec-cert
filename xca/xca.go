package xca

import (
	"bytes"
	"crypto/x509"
	"sync"

	"github.com/andrewz1/xtoml"

	"github.com/andrewz1/ipsec-cert/xt"
)

const (
	sysBundle = "/etc/ssl/certs/ca-certificates.crt"
)

type Conf struct {
	Bundle string `conf:"ca.bundle"`
}

type xca struct {
	sync.RWMutex
	roots []*x509.Certificate
	certs []*x509.Certificate
}

var (
	opt = &Conf{
		Bundle: sysBundle,
	}
	sysRoots *x509.CertPool
	ca       xca
)

func Init(xc *xtoml.XConf) error {
	err := xc.LoadConf(opt)
	if err != nil {
		return err
	}
	if sysRoots, err = x509.SystemCertPool(); err != nil {
		return err
	}
	if ca.roots, err = xt.LoadCertsFromFile(sysBundle); err != nil {
		return err
	}
	if opt.Bundle != sysBundle { // add certs from custom bundle (for staging)
		var roots []*x509.Certificate
		if roots, err = xt.LoadCertsFromFile(opt.Bundle); err != nil {
			return err
		}
		for _, root := range roots {
			sysRoots.AddCert(root)
		}
		ca.roots = append(ca.roots, roots...)
	}
	return nil
}

func AddCert(crt ...*x509.Certificate) {
	ca.Lock()
	defer ca.Unlock()
	if ca.certs != nil {
		ca.certs = ca.certs[:0]
	}
	ca.certs = append(ca.certs, crt...)
}

func parentByKey(ca []*x509.Certificate, cc *x509.Certificate) *x509.Certificate {
	if len(cc.AuthorityKeyId) == 0 {
		return nil
	}
	for _, c := range ca {
		if bytes.Equal(cc.AuthorityKeyId, c.SubjectKeyId) {
			return c
		}
	}
	return nil
}

func parentByName(ca []*x509.Certificate, cc *x509.Certificate) *x509.Certificate {
	name := cc.Issuer.String()
	if len(name) == 0 {
		return nil
	}
	for _, c := range ca {
		if name == c.Subject.String() {
			return c
		}
	}
	return nil
}

func parent(ca []*x509.Certificate, cc *x509.Certificate) *x509.Certificate {
	if crt := parentByKey(ca, cc); crt != nil {
		return crt
	}
	return parentByName(ca, cc)
}

func GetParent(crt *x509.Certificate) *x509.Certificate {
	ca.RLock()
	defer ca.RUnlock()
	if rv := parent(ca.certs, crt); rv != nil {
		return rv
	}
	return parent(ca.roots, crt)
}

func IsRoot(crt *x509.Certificate) bool {
	if len(crt.SubjectKeyId) > 0 && len(crt.AuthorityKeyId) > 0 {
		return bytes.Equal(crt.SubjectKeyId, crt.AuthorityKeyId)
	}
	return crt.Issuer.String() == crt.Subject.String()
}

func SysPool() *x509.CertPool {
	return sysRoots
}
