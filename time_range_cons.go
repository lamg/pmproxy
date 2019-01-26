package pmproxy

import (
	"encoding/json"
	"github.com/lamg/clock"
	rt "github.com/lamg/rtimespan"
)

// trCons is a time range consumption limiter
// for a connection
type trCons struct {
	Name string    `json:"name"`
	Span *rt.RSpan `json:"span"`

	clock clock.Clock
}

func (t *trCons) consR() (c *consR) {
	c = &consR{
		open: func(ip string) (ok bool) {
			tm := t.clock.Now()
			ok = t.Span.ContainsTime(tm)
			return
		},
		can: func(ip string, down int) (ok bool) {
			tm := t.clock.Now()
			ok = t.Span.ContainsTime(tm)
			return
		},
		update: func(ip string, down int) {},
		close:  func(ip string) {},
	}
	return
}

func (t *trCons) admin(c *AdmCmd, fb fbs,
	fe ferr) (cs []cmdProp) {
	if c.IsAdmin {
		cs = []cmdProp{
			{
				cmd:  get,
				prop: spanK,
				f: func() {
					bs, e := json.Marshal(t.Span)
					fb(bs)
					fe(e)
				},
			},
			{
				cmd:  set,
				prop: spanK,
				f:    func() { t.Span = c.Span },
			},
		}
	}
	return
}

const (
	trConsT = "trCons"
)

func (t *trCons) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		nameK:     t.Name,
		startK:    t.Span.Start.String(),
		activeK:   t.Span.Active.String(),
		totalK:    t.Span.Total.String(),
		timesK:    t.Span.Times,
		infiniteK: t.Span.Infinite,
		allTimeK:  t.Span.AllTime,
	}
	tỹpe = trConsT
	return
}

func (t *trCons) fromMap(fe ferr) (kf []kFuncI) {
	t.Span = new(rt.RSpan)
	kf = []kFuncI{
		{
			nameK,
			func(i interface{}) {
				t.Name = stringE(i, fe)
			},
		},
	}
	kf = append(kf, fromMapKFSpan(t.Span, fe)...)
	return
}
