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

func toSerSpan(s *rt.RSpan) (m map[string]interface{}) {
	m = map[string]interface{}{
		startK:    s.Start.String(),
		activeK:   s.Active.String(),
		totalK:    s.Total.String(),
		infiniteK: s.Infinite,
		allTimeK:  s.AllTime,
	}
	return
}

func fromMapKFSpan(s *rt.RSpan, fe ferr) (kf []kFuncI) {
	kf = []kFuncI{
		{
			activeK,
			func(i interface{}) {
				s.Active = stringDurationE(i, fe)
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
				s.Total = stringDurationE(i, fe)
			},
		},
	}
	return
}
