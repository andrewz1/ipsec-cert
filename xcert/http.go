package xcert

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/crypto/acme"

	"github.com/andrewz1/ipsec-cert/xacme"
)

const (
	httpChal = "http-01"
)

func getChallenge(a *acme.Authorization) *acme.Challenge {
	for _, cc := range a.Challenges {
		if cc.Type == httpChal {
			return cc
		}
	}
	return nil
}

func runHTTP(ctx context.Context, z *acme.Authorization) error {
	cc := getChallenge(z)
	if cc == nil {
		return fmt.Errorf(`challenge type "%s" not supported`, httpChal)
	}
	body, err := xacme.HTTP01ChallengeResponse(cc.Token)
	if err != nil {
		return err
	}
	m := http.NewServeMux()
	m.HandleFunc(xacme.HTTP01ChallengePath(cc.Token), func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
		r.Body.Close()
	})
	srv := &http.Server{Handler: m}
	ln, err := newListener("tcp", opt.Bind...)
	if err != nil {
		return err
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		srv.Serve(ln)
		ln.Close()
		wg.Done()
	}()
	defer func() {
		srv.Shutdown(ctx)
		wg.Wait()
	}()
	if _, err = xacme.Accept(ctx, cc); err != nil {
		return err
	}
	if _, err = xacme.WaitAuthorization(ctx, z.URI); err != nil {
		return err
	}
	return nil
}
