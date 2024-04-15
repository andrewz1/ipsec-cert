package xcert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/andrewz1/xlog"

	"github.com/andrewz1/ipsec-cert/xca"
	"github.com/andrewz1/ipsec-cert/xt"
)

const (
	updateBefore = time.Hour * 24 * 32 // 32 days before end
)

var (
	tlsFeatureExtensionOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}
	ocspMustStapleFeature  = []byte{0x30, 0x03, 0x02, 0x01, 0x05}
	ocspMustStaple         = pkix.Extension{Id: tlsFeatureExtensionOID, Value: ocspMustStapleFeature}
)

func certName(n int) string {
	return strings.NewReplacer(numTag, strconv.Itoa(n)).Replace(opt.CaPath)
}

func certNames() []string {
	tmp := make([]string, 0, 10)
	if !xt.CheckFile(opt.Cert) {
		return nil
	}
	tmp = append(tmp, opt.Cert)
	if opt.Split {
		if opt.haveNum {
			n := 0
			for {
				n++
				name := certName(n)
				if xt.CheckFile(name) {
					tmp = append(tmp, name)
				} else {
					break
				}
			}
		} else {
			if xt.CheckFile(opt.CaPath) {
				tmp = append(tmp, opt.CaPath)
			}
		}
	}
	return tmp
}

func (cs *certStore) resetCert() {
	cs.cert = nil
	if cs.roots != nil {
		cs.roots = cs.roots[:0]
	}
}

func buildChain(in []*x509.Certificate) (*x509.Certificate, []*x509.Certificate) {
	start := in[0]
	xca.AddCert(in[1:]...)
	chain := make([]*x509.Certificate, 0, len(in))
	for {
		if xca.IsRoot(start) {
			break
		}
		rv := xca.GetParent(start)
		if rv == nil {
			break
		}
		chain = append(chain, rv)
		start = rv
	}
	return in[0], chain
}

func (cs *certStore) loadFiles() error {
	cs.resetCert()
	names := certNames()
	if len(names) == 0 {
		return fmt.Errorf("no certificates found")
	}
	certs := make([]*x509.Certificate, 0, 10)
	for _, n := range names {
		cc, err := xt.LoadCertsFromFile(n)
		if err != nil {
			return fmt.Errorf("could not load certificate '%s': %v", n, err)
		}
		certs = append(certs, cc...)
	}
	if len(certs) == 0 {
		return fmt.Errorf("no certificates loaded")
	}
	cs.cert, cs.roots = buildChain(certs)
	return nil
}

func (cs *certStore) verifyCerts() error {
	inter := x509.NewCertPool()
	for _, cert := range cs.roots {
		inter.AddCert(cert)
	}
	opts := x509.VerifyOptions{
		Intermediates: inter,
		Roots:         xca.SysPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	for _, n := range opt.Id {
		opts.DNSName = n
		if _, err := cs.cert.Verify(opts); err != nil {
			return fmt.Errorf("failed to verify %s: %v", n, err)
		}
	}
	return nil
}

func (cs *certStore) verifyKey() error {
	type pubKey interface {
		Public() crypto.PublicKey
	}
	type pubEq interface {
		Equal(crypto.PublicKey) bool
	}
	pub, ok := cs.key.(pubKey)
	if !ok {
		return fmt.Errorf("%s: invalid private key", opt.Key)
	}
	eq, ok := pub.Public().(pubEq)
	if !ok {
		return fmt.Errorf("%s: invalid public key", opt.Key)
	}
	if !eq.Equal(cs.cert.PublicKey) {
		return fmt.Errorf("%s: private key not match", opt.Key)
	}
	return nil
}

func (cs *certStore) makeCSR() {
	cs.csr = &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: opt.Id[0]},
		DNSNames: opt.Id,
	}
	if opt.Staple {
		cs.csr.ExtraExtensions = []pkix.Extension{ocspMustStaple}
	}
}

func (cs *certStore) loadCerts() {
	err := cs.loadFiles()
	if err != nil {
		xlog.Warn(err)
		return
	}
	// verify cert
	if err = cs.verifyCerts(); err != nil {
		cs.resetCert()
		xlog.Warn(err)
		return
	}
	// verify key
	if err = cs.verifyKey(); err != nil {
		cs.resetCert()
		xlog.Warn(err)
		return
	}
	// save roots
	xca.AddCert(cs.roots...)
}

func (cs *certStore) getCSR() ([]byte, error) {
	if cs.csr == nil {
		cs.makeCSR()
	}
	return x509.CreateCertificateRequest(rand.Reader, cs.csr, cs.key)
}
