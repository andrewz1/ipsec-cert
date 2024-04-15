package xt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"
)

func LoadCertsFromFile(name string) ([]*x509.Certificate, error) {
	buf, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var pb *pem.Block
	var crt *x509.Certificate
	var rv = make([]*x509.Certificate, 0, 200)
	for {
		if pb, buf = pem.Decode(buf); pb == nil {
			break
		}
		if crt, err = x509.ParseCertificate(pb.Bytes); err != nil {
			return nil, err
		}
		rv = append(rv, crt)
	}
	return rv, nil
}

func ParsePrivateKey(der []byte) (crypto.Signer, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch v := key.(type) {
		case *rsa.PrivateKey:
			return v, nil
		case *ecdsa.PrivateKey:
			return v, nil
		default:
			return nil, fmt.Errorf("unsupported key type %T", v)
		}
	}
	return nil, fmt.Errorf("unknown key type")
}

func LoadKeyFromFile(name string) (crypto.Signer, error) {
	buf, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	pb, _ := pem.Decode(buf)
	if pb == nil {
		return nil, fmt.Errorf("invalid key format")
	}
	k, err := ParsePrivateKey(pb.Bytes)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func SaveDerToFile(raw []byte, pemType, pemFile string, mode os.FileMode) error {
	pemData := pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: raw})
	if err := MakeDirsForFile(pemFile); err != nil {
		return err
	}
	if err := os.WriteFile(pemFile, pemData, mode); err != nil {
		os.Remove(pemFile)
		return err
	}
	return nil
}

func SaveDerToWriter(raw []byte, pemType string, w io.Writer) error {
	return pem.Encode(w, &pem.Block{Type: pemType, Bytes: raw})
}

func SaveCertsToFile(certs []*x509.Certificate, name string, mode os.FileMode) error {
	err := MakeDirsForFile(name)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		if err != nil {
			os.Remove(name)
		}
	}()
	for _, v := range certs {
		if err = SaveDerToWriter(v.Raw, "CERTIFICATE", f); err != nil {
			return err
		}
	}
	return nil
}

func SaveCertToFile(cert *x509.Certificate, name string, mode os.FileMode) error {
	err := MakeDirsForFile(name)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer func() {
		f.Close()
		if err != nil {
			os.Remove(name)
		}
	}()
	if err = SaveDerToWriter(cert.Raw, "CERTIFICATE", f); err != nil {
		return err
	}
	return nil
}
