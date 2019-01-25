package pmproxy

import (
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
		open: func(i ip) (ok bool) {
			tm := t.clock.Now()
			ok = t.Span.ContainsTime(tm)
			return
		},
		can: func(i ip) (ok bool) {
			tm := t.clock.Now()
			ok = t.Span.ContainsTime(tm)
			return
		},
		update: func(i ip, d download) {},
		close:  func(i ip) {},
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

func (t *trCons) fromMap(i interface{}) (e error) {
	t.Span = new(rt.RSpan)
	kf := []struct {
		k string
		f func(interface{})
	}{
		{
			nameK,
			func(i interface{}) {
				t.Name, e = cast.ToStringE(i)
			},
		},
		{
			startK,
			func(i interface{}) {
				t.Span.Start, e = cast.StringToDate(i)
			},
		},
		{
			activeK,
			func(i interface{}) {
				t.Span.Active, e = stringToDuration(i)
			},
		},
		{
			totalK,
			func(i interface{}) {
				t.Span.Total, e = stringToDuration(i)
			},
		},
		{
			timesK,
			func(i interface{}) {
				t.Span.Times, e = cast.ToIntE(i)
			},
		},
		{
			infiniteK,
			func(i interface{}) {
				t.Span.Infinite, e = cast.ToBoolE(i)
			},
		},
		{
			allTimeK,
			func(i interface{}) {
				t.Span.AllTime, e = cast.ToBoolE(i)
			},
		},
	}
	mapKF(
		fe,
		i,
		func(d error) { e = d },
		func() bool { return e != nil },
	)
	return
}
