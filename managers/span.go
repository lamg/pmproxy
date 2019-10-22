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
