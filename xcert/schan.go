package xcert

import (
	"sync"
)

type SChan struct {
	sync.RWMutex
	closed bool
	C      chan any
}

func (s *SChan) Close() bool {
	s.Lock()
	defer s.Unlock()
	if !s.closed {
		close(s.C)
		s.closed = true
		return true
	}
	return false
}

func (s *SChan) Put(v any) bool {
	s.RLock()
	defer s.RUnlock()
	if !s.closed {
		s.C <- v
		return true
	}
	return false
}

func NewSChan(len int) SChan {
	return SChan{C: make(chan any, len)}
}
