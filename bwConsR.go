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
	"fmt"
	"github.com/lamg/throttle"
	"github.com/spf13/cast"
	"time"
)

type bwConsR struct {
	name    string
	thrFrac float64
	connThr *throttle.Throttle
	spec    *spec
}

func (b *bwConsR) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				b.name = stringE(i, fe)
			},
		},
		{
			throttleK,
			func(i interface{}) {
				var d error
				b.thrFrac, d = cast.ToFloat64E(i)
				fe(d)
			},
		},
		{
			specKS,
			func(i interface{}) {
				// optional field in map
				b.spec = new(spec)
				b.spec.fromMap(i)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (b *bwConsR) toMap() (i map[string]interface{}) {
	i = map[string]interface{}{
		nameK:     b.name,
		throttleK: fmt.Sprintf("%.2f", b.thrFrac),
	}
	return
}

func (b *bwConsR) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			get,
			func() {
				c.bs = []byte(fmt.Sprintf("%.2f", b.thrFrac))
			},
		},
		{
			set,
			func() {
				var nFrac float64
				_, e := fmt.Scanf("%.2f", &nFrac)
				if e == nil {
					b.thrFrac, b.connThr = nFrac,
						throttle.NewThrottle(nFrac, time.Millisecond)
				}
			},
		},
	}
	return
}

func (b *bwConsR) consR() (c *consR) {
	c = &consR{
		open: func(ip, user string) (ok bool) {
			ok = true
			return
		},
		can: func(ip, user string, dwn int) (ok bool) {
			b.connThr.Throttle()
			ok = true
			return
		},
		update: func(ip, user string, dwn int) {},
		close:  func(ip, user string) {},
	}
	return
}
