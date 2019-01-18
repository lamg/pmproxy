package pmproxy

import (
	"github.com/lamg/clock"
	rt "github.com/lamg/rtimespan"
)

// trCons is a time range consumption limiter for a connection
type trCons struct {
	Name string    `json:"name"`
	Span *rt.RSpan `json:"span"`

	clock clock.Clock
}

func (t *trCons) manager() (m *manager) {
	m = &manager{
		name: t.Name,
		tỹpe: "trCons",
		cons: &consR{
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
		},
		adm: func(c *AdmCmd) (bs []byte, e error) {
			switch c.Cmd {
			case "get-span":
				bs, e = json.Marshal(t.Span)
			case "set-span":
				t.Span = c.Span
			default:
				e = NoCmd(c.Cmd)
			}
			return
		},
		toSer: func() (i interface{}) {
			i = map[string]interface{}{
				nameK: t.Name,
				spanK: toSer(t.Span),
			}
			return
		},
	}
	return
}

func toSer(r *rt.Span) (m map[string]interface{}) {
	m = map[string]interface{}{
		startK:    r.Start.String(),
		activeK:   r.Active.String(),
		totalK:    r.Total.String(),
		timesK:    r.Times,
		infiniteK: r.Infinite,
		allTimeK:  r.AllTime,
	}
	return
}
