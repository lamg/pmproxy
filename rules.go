package pmproxy

import (
	"context"
	"github.com/lamg/proxy"
	"time"
	"url"
)

type rules struct {
}

func readRules() (r *rules, e error) {
	v := viper.Get("rules")
	return
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
