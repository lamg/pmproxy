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
	"github.com/lamg/proxy"
	"time"
)

// connMng has the values for controlling how
// the proxy (github.com/lamg/proxy) handles the connection
type connMng struct {
	maxIdle int
	idleT   time.Duration
	tlsHT   time.Duration
	expCT   time.Duration

	// these are initialized at conf.go
	direct proxy.ContextDialer
	proxyF proxy.ParentProxyF
	ctxVal proxy.ContextValueF
}

func (p *connMng) toMap() (i interface{}) {
	i = map[string]interface{}{
		nameK:    proxyTr,
		maxIdleK: p.maxIdle,
		idleTK:   p.idleT,
		tlsHTK:   p.tlsHT,
		expCTK:   p.expCT,
	}
	return
}

func (p *connMng) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			maxIdleK,
			func(i interface{}) {
				p.maxIdle = intE(i, fe)
			},
		},
		{
			idleTK,
			func(i interface{}) {
				p.idleT = durationE(i, fe)
			},
		},
		{
			tlsHTK,
			func(i interface{}) {
				p.tlsHT = durationE(i, fe)
			},
		},
		{
			expCTK,
			func(i interface{}) {
				p.expCT = durationE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}
