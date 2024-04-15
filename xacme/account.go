package xacme

import (
	"context"
	"crypto/elliptic"
	"sync"
	"time"

	"github.com/andrewz1/xlog"
	"golang.org/x/crypto/acme"

	"github.com/andrewz1/ipsec-cert/xt"
)

type client struct {
	sync.Mutex
	cl  *acme.Client
	acc *acme.Account
}

var (
	cl client
)

func dirURL() string {
	if opt.Staging {
		return LEStaging
	}
	return LEMain
}

func (c *client) init() {
	c.Lock()
	defer c.Unlock()
	if c.cl == nil {
		c.cl = &acme.Client{DirectoryURL: dirURL()}
	}
	if c.acc != nil {
		return
	}
	if c.checkKey() {
		return
	}
	if err := c.regKey(); err != nil {
		xlog.Fatalf("failed to register key: %v", err)
	}
}

// load and check existing key
func (c *client) checkKey() bool {
	if !xt.CheckFile(opt.AcmeKey) {
		return false
	}
	var err error
	if c.cl.Key, err = xt.LoadKeyFromFile(opt.AcmeKey); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	acc, err := c.cl.GetReg(ctx, "")
	if err != nil {
		xlog.Warnf("%v", err)
		return false
	}
	if acc.Status != acme.StatusValid {
		xlog.Warnf("acme account status is: %s", acc.Status)
		return false
	}
	c.acc = acc
	return true
}

// generate and save new key
func (c *client) regKey() error {
	xlog.Warnf("generate new key %s", opt.AcmeKey)
	var raw []byte
	var err error
	if c.cl.Key, raw, err = xt.GenerateECKey(elliptic.P384()); err != nil {
		return err
	}
	accT := &acme.Account{}
	if len(opt.AcmeEmail) > 0 {
		accT.Contact = []string{"mailto:" + opt.AcmeEmail}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	acc, err := c.cl.Register(ctx, accT, acme.AcceptTOS)
	if err != nil {
		return err
	}
	if err = xt.SaveDerToFile(raw, "PRIVATE KEY", opt.AcmeKey, 0600); err != nil {
		return err
	}
	c.acc = acc
	return nil
}

func HTTP01ChallengeResponse(token string) (string, error) {
	cl.init()
	return cl.cl.HTTP01ChallengeResponse(token)
}

func HTTP01ChallengePath(token string) string {
	cl.init()
	return cl.cl.HTTP01ChallengePath(token)
}

func Accept(ctx context.Context, chal *acme.Challenge) (*acme.Challenge, error) {
	cl.init()
	return cl.cl.Accept(ctx, chal)
}

func WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	cl.init()
	return cl.cl.WaitAuthorization(ctx, url)
}

func AuthorizeOrder(ctx context.Context, id []acme.AuthzID, opt ...acme.OrderOption) (*acme.Order, error) {
	cl.init()
	return cl.cl.AuthorizeOrder(ctx, id, opt...)
}

func RevokeAuthorization(ctx context.Context, url string) error {
	cl.init()
	return cl.cl.RevokeAuthorization(ctx, url)
}

func GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	cl.init()
	return cl.cl.GetAuthorization(ctx, url)
}

func WaitOrder(ctx context.Context, url string) (*acme.Order, error) {
	cl.init()
	return cl.cl.WaitOrder(ctx, url)
}

func CreateOrderCert(ctx context.Context, url string, csr []byte, bundle bool) (der [][]byte, certURL string, err error) {
	cl.init()
	return cl.cl.CreateOrderCert(ctx, url, csr, bundle)
}
