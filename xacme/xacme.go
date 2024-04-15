package xacme

import (
	"github.com/andrewz1/xtoml"
	"golang.org/x/crypto/acme"
)

const (
	LEMain    = acme.LetsEncryptURL // "https://acme-v02.api.letsencrypt.org/directory"
	LEStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

type Conf struct {
	Staging   bool   `conf:"acme.staging"`
	AcmeKey   string `conf:"acme.key,required"`
	AcmeEmail string `conf:"acme.email"`
}

var (
	opt = &Conf{}
)

func Init(xc *xtoml.XConf) error {
	err := xc.LoadConf(opt)
	if err != nil {
		return err
	}
	return nil
}
