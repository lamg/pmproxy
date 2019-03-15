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
		startK:    s.Start.String(),
		activeK:   s.Active.String(),
		totalK:    s.Total.String(),
		infiniteK: s.Infinite,
		allTimeK:  s.AllTime,
		nameK:     name,
	}
	return
}

func fromMapSpan(s *rt.RSpan,
	i interface{}) (name string, e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			nameK, func(i interface{}) { name = stringE(i, fe) },
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
