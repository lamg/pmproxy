package pmproxy

import (
	"context"
	"github.com/lamg/proxy"
	"net/url"
	"time"
)

type rules struct {
}

func (r *rules) evaluators() (pf proxy.ParentProxyF,
	cv proxy.ContextValueF) {
	cv := func(ctx context.Context, method, ürl, rAddr string,
		t time.Time,
	) (nctx context.Context) {
		return
	}
	pf := func(method, ürl, rAddr strig,
		t time.Time) (u *url.URL, e error) {
		return
	}
	return
}
