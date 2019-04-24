// Copyright © 2017-2019 Luis Ángel Méndez Gort

// This file is part of PMProxy.

// PMProxy is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.

// PMProxy is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Affero General Public
// License for more details.

// You should have received a copy of the GNU Affero General
// Public License along with PMProxy.  If not, see
// <https://www.gnu.org/licenses/>.

package pmproxy

import (
	rt "github.com/lamg/rtimespan"
	"github.com/spf13/cast"
	"time"
)

const (
	startK    = "start"
	activeK   = "active"
	totalK    = "total"
	timesK    = "times"
	infiniteK = "infinite"
	allTimeK  = "allTime"
)

func toMapSpan(s *rt.RSpan,
	name string) (m map[string]interface{}) {
	m = map[string]interface{}{
		startK:    s.Start.Format(time.RFC3339),
		activeK:   s.Active.String(),
		totalK:    s.Total.String(),
		infiniteK: s.Infinite,
		allTimeK:  s.AllTime,
		timesK:    s.Times,
		nameK:     name,
	}
	return
}

func fromMapSpan(s *rt.RSpan,
	i interface{}) (name string, e error) {
	fe := func(d error) { e = d }
	optFe := optionalKeys(fe, allTimeK, infiniteK, timesK)
	kf := []kFuncI{
		{
			nameK, func(i interface{}) { name = stringE(i, fe) },
		},
		{
			timesK,
			func(i interface{}) {
				s.Times, _ = cast.ToIntE(i)
			},
		},
		{
			activeK,
			func(i interface{}) {
				s.Active = durationE(i, fe)
			},
		},
		{
			allTimeK,
			func(i interface{}) {
				s.AllTime, _ = cast.ToBoolE(i)
			},
		},
		{
			infiniteK,
			func(i interface{}) {
				s.Infinite, _ = cast.ToBoolE(i)
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
	mapKF(kf, i, optFe, func() bool { return e == nil })
	return
}
