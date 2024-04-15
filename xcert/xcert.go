package xcert

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/andrewz1/xtoml"
)

const (
	numTag = "%NUM%"
)

type certStore struct {
	key    crypto.PrivateKey        // private key
	keyRaw []byte                   // key raw DER data
	cert   *x509.Certificate        // base cert
	roots  []*x509.Certificate      // cert roots
	csr    *x509.CertificateRequest // cert request
}

type Conf struct {
	Id     []string `conf:"cert.id,required"`
	Key    string   `conf:"cert.key,required"`
	Cert   string   `conf:"cert.cert,required"`
	Type   string   `conf:"cert.type"`
	Bits   int      `conf:"cert.bits"`
	Bind   []string `conf:"cert.bind"`
	Staple bool     `conf:"cert.must_staple"`
	Split  bool     `conf:"cert.split"`
	CaPath string   `conf:"cert.ca"`
	Script string   `conf:"cert.script"`

	haveNum bool
}

var (
	opt = &Conf{
		Type: "rsa",
		Bind: []string{":80"},
	}
	cst certStore
)

func Init(xc *xtoml.XConf) error {
	err := xc.LoadConf(opt)
	if err != nil {
		return err
	}
	if opt.Split {
		if len(opt.CaPath) == 0 {
			return fmt.Errorf("cert.ca must be set if cert.split is true")
		}
	}
	opt.haveNum = strings.Contains(opt.CaPath, numTag)
	if err = cst.loadOrGenKey(); err != nil {
		return err
	}
	cst.loadCerts()
	go cst.updateMain()
	return nil
}
