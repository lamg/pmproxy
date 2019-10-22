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
	"fmt"
	alg "github.com/lamg/algorithms"
	"github.com/lamg/throttle"
	"time"
)

type bwConsR struct {
	name    string
	thrFrac float64
	connThr *throttle.Throttle
}

const (
	BwConsRK = "bwConsR"
)

func (b *bwConsR) exec(c *Cmd) {
	kf := []alg.KFunc{
		{
			Get,
			func() {
				c.Data = []byte(fmt.Sprintf("%.2f", b.thrFrac))
			},
		},
		{
			Set,
			func() {
				var nFrac float64
				_, e := fmt.Scanf("%.2f", &nFrac)
				if e == nil {
					b.thrFrac, b.connThr = nFrac,
						throttle.NewThrottle(nFrac, time.Millisecond)
				}
			},
		},
		{readRequest, func() { b.connThr.Throttle() }},
		{readReport, func() {}},
		{
			Match,
			func() {
				c.interp[b.name], c.consR =
					&MatchType{Match: true, Type: "bwConsR"},
					append(c.consR, b.name)
			},
		},
	}
	c.Ok = alg.ExecF(kf, c.Cmd)
}
