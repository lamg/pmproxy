package pmproxy

import (
	rt "github.com/lamg/rtimespan"
)

const (
	startK    = "start"
	activeK   = "active"
	totalK    = "total"
	timesK    = "times"
	infiniteK = "infinite"
	allTimeK  = "allTime"
)

func toMapSpan(s *rt.RSpan) (m map[string]interface{}) {
	m = map[string]interface{}{
		startK:    s.Start.String(),
		activeK:   s.Active.String(),
		totalK:    s.Total.String(),
		infiniteK: s.Infinite,
		allTimeK:  s.AllTime,
	}
	return
}

func fromMapSpan(s *rt.RSpan, i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			activeK,
			func(i interface{}) {
				s.Active = durationE(i, fe)
			},
		},
		{
			allTimeK,
			func(i interface{}) {
				s.AllTime = boolE(i, fe)
			},
		},
		{
			infiniteK,
			func(i interface{}) {
				s.Infinite = boolE(i, fe)
			},
		},
		{
			startK,
			func(i interface{}) {
				s.Start = stringDateE(i, fe)
			},
		},
		{
			totalK,
			func(i interface{}) {
				s.Total = durationE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}
