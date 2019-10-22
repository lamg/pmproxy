package managers

import (
	alg "github.com/lamg/algorithms"
	rt "github.com/lamg/rtimespan"
	"time"
)

type span struct {
	Span *rt.RSpan `toml:"span"`
	Name string    `toml:"name"`
	now  func() time.Time
}

func (s *span) exec(c *Cmd) {
	kf := []alg.KFunc{
		{
			Match,
			func() {
				c.Ok = s.Span.ContainsTime(s.now())
				c.interp[s.Name] = &MatchType{
					Type:  SpanK,
					Match: c.Ok,
				}
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
}
