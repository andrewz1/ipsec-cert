package xcert

import (
	"net"
)

const (
	chanLen = 100
)

type mListener struct {
	ln []net.Listener
	ch SChan
}

func (l *mListener) Accept() (net.Conn, error) {
	for c := range l.ch.C {
		return c.(net.Conn), nil
	}
	return nil, net.ErrClosed
}

func (l *mListener) closeListeners() {
	for _, ln := range l.ln {
		_ = ln.Close()
	}
}

func (l *mListener) closeConns() {
	for cn := range l.ch.C {
		_ = cn.(net.Conn).Close()
	}
}

func (l *mListener) closeAll() bool {
	if !l.ch.Close() {
		return false
	}
	l.closeListeners() // close listeners
	l.closeConns()     // close not accepted connections
	return true
}

func (l *mListener) Close() error {
	if l.closeAll() {
		return nil
	}
	return net.ErrClosed
}

func (l *mListener) Addr() net.Addr {
	return l.ln[0].Addr() // return first listener addr
}

func (l *mListener) acceptOne(ln net.Listener) {
	for {
		cn, err := ln.Accept()
		if err != nil {
			break
		}
		if !l.ch.Put(cn) {
			_ = cn.Close()
			break
		}
	}
	_ = ln.Close()
}

func newListener(network string, address ...string) (*mListener, error) {
	if len(address) == 0 {
		return nil, net.InvalidAddrError("invalid address")
	}
	l := &mListener{
		ln: make([]net.Listener, 0, len(address)),
		ch: NewSChan(chanLen),
	}
	for _, a := range address {
		if ln, err := net.Listen(network, a); err != nil {
			l.closeListeners()
			return nil, err
		} else {
			l.ln = append(l.ln, ln)
		}
	}
	for _, ln := range l.ln {
		go l.acceptOne(ln)
	}
	return l, nil
}
