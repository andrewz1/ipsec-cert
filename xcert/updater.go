package xcert

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/andrewz1/xlog"
	"golang.org/x/crypto/acme"

	"github.com/andrewz1/ipsec-cert/xacme"
	"github.com/andrewz1/ipsec-cert/xca"
	"github.com/andrewz1/ipsec-cert/xt"
)

func (cs *certStore) updateIn() time.Duration {
	if cs.cert == nil {
		return 0
	}
	d := cs.cert.NotAfter.Sub(time.Now())
	if d > updateBefore {
		return d - updateBefore
	}
	return 0
}

func (cs *certStore) rebuildChain() bool {
	chain := make([]*x509.Certificate, 0, 10)
	start := cs.cert
	isFull := false
	for {
		if xca.IsRoot(start) {
			isFull = true
			break
		}
		rv := xca.GetParent(start)
		if rv == nil {
			break
		}
		chain = append(chain, rv)
		start = rv
	}
	cs.roots = chain
	return isFull
}

func (cs *certStore) update() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	ord, err := xacme.AuthorizeOrder(ctx, acme.DomainIDs(opt.Id...))
	if err != nil {
		return err
	}
	var urls []string
	defer func() {
		for _, v := range urls {
			xacme.RevokeAuthorization(ctx, v)
		}
	}()
	var z *acme.Authorization
	for _, u := range ord.AuthzURLs {
		if z, err = xacme.GetAuthorization(ctx, u); err != nil {
			return err
		}
		if z.Status != acme.StatusPending {
			continue
		}
		if err = runHTTP(ctx, z); err != nil {
			return err
		}
		urls = append(urls, z.URI)
	}
	if _, err = xacme.WaitOrder(ctx, ord.URI); err != nil {
		return err
	}
	csr, err := cs.getCSR()
	if err != nil {
		return err
	}
	der, _, err := xacme.CreateOrderCert(ctx, ord.FinalizeURL, csr, true)
	if err != nil {
		return err
	} else if len(der) == 0 {
		return fmt.Errorf("invalid certificate bundle")
	}
	cert := make([]*x509.Certificate, 0, len(der))
	var crt *x509.Certificate
	for _, one := range der {
		if crt, err = x509.ParseCertificate(one); err != nil {
			return err
		}
		cert = append(cert, crt)
	}
	// build chain
	cs.cert, cs.roots = buildChain(cert)
	if err = cs.saveCerts(); err != nil {
		return err
	}
	if e := runScript(); e != nil {
		xlog.Warnf("script: %v", e)
	}
	return nil
}

func (cs *certStore) updateMain() {
	for {
		if d := cs.updateIn(); d > 0 {
			xlog.Infof("next update in %v", d)
			time.Sleep(d)
			continue
		}
		if err := cs.update(); err != nil {
			cs.resetCert()
			xlog.Warnf("update error: %v", err)
			time.Sleep(4 * time.Hour)
			continue
		}
		time.Sleep(10 * time.Second)
	}
}

func (cs *certStore) saveCerts() error {
	if opt.Split {
		if err := xt.SaveCertToFile(cs.cert, opt.Cert, 0644); err != nil {
			return err
		}
		if !opt.haveNum {
			return xt.SaveCertsToFile(cs.roots, opt.CaPath, 0644)
		}
		for i, v := range cs.roots {
			if err := xt.SaveCertToFile(v, certName(i+1), 0644); err != nil {
				return err
			}
		}
		return nil
	} else {
		return xt.SaveCertsToFile(append([]*x509.Certificate{cs.cert}, cs.roots...), opt.Cert, 0644)
	}
}
