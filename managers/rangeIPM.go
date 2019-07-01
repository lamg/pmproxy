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
	"net"
)

type rangeIPM struct {
	rg   *net.IPNet
	cidr string
	name string
}

const (
	RangeIPMK = "rangeIPM"
)

func (r *rangeIPM) init() (e error) {
	_, r.rg, e = net.ParseCIDR(r.cidr)
	return
}

func (r *rangeIPM) exec(c *Cmd) (term bool) {
	kf := []alg.KFunc{
		{
			Get,
			func() {
				c.Data = []byte(r.cidr)
			},
		},
		{
			Match,
			func() {
				c.interp[r.name], term =
					MatchType{
						Match: r.match(c.IP),
						Type:  RangeIPMK,
					},
					true
			},
		},
		{
			Type,
			func() {
				c.Data = []byte(RangeIPMK)
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
