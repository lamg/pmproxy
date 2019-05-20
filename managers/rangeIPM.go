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
	"net"
)

type rangeIPM struct {
	rg   *net.IPNet
	cidr string
	name string
}

func (r *rangeIPM) init() (e error) {
	_, r.rg, e = net.ParseCIDR(r.cidr)
	return
}

func (r *rangeIPM) exec(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			Get,
			func() {
				c.bs = []byte(r.cidr)
			},
		},
		{
			Match,
			func() {
				c.Ok = r.match(c.IP)
				term = true
			},
		},
	}
	alg.ExecF(kf, c.Cmd)
	return
}

func (r *rangeIPM) match(ip string) (ok bool) {
	pip := net.ParseIP(ip)
	ok = pip != nil && r.rg.Contains(pip)
	return
}

func (r *rangeIPM) toMap() (i map[string]interface{}) {
	i = map[string]interface{}{
		NameK: r.name,
		cidrK: r.cidr,
	}
	return
}

func (r *rangeIPM) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			NameK,
			func(i interface{}) {
				r.name = stringE(i, fe)
			},
		},
		{
			cidrK,
			func(i interface{}) {
				r.cidr = stringE(i, fe)
			},
		},
		{
			cidrK, // if previous keys exists this exists and
			// r.init is executed
			func(i interface{}) {
				e = r.init()
			},
		},
	}
	fb := func() bool { return e == nil }
	mapKF(kf, i, fe, fb)
	return
}
