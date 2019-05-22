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
	mng "github.com/lamg/pmproxy/managers"
)

func loadSrvConf(fs afero.Fs) (prx, iface *srvConf, e error) {
	return
}

type srvConf struct {
	name         string
	iface        *ifaceConf
	prx          *proxyConf
	readTimeout  time.Duration
	writeTimeout time.Duration
	addr         string

	fast *fastSrv
	std  *stdSrv
}

type fastSrv struct {
	maxConnIP  int
	maxReqConn int
}

type stdSrv struct {
	maxIdle time.Duration
	idleT   time.Duration
	tlsHT   time.Duration
	expCT   time.Duration
}

type ifaceConf struct {
	certFl      string
	keyFl       string
	cmdChan     mng.CmdF
	staticFPath string
	persistIntv time.Duration
	persist     func() error
}

type proxyConf struct {
	ctl         proxy.ControlConn
	dialTimeout time.Duration
	now         func() time.Time
}

func readSrvConf(i interface{}) (sc *srvConf, e error) {
	sc = new(srvConf)
	fe := func(d error) {
		if d != nil {
			s := d.Error()
			me := NoKey(maxConnIPK).Error()
			re := NoKey(maxReqConnK).Error()
			if s == me || s == re {
				d = nil
			}
		}
		e = d
	}
	kf := []kFuncI{
		{
			fastOrStdK,
			func(i interface{}) {
				sc.fastOrStd = boolE(i, fe)
			},
		},
		{
			readTimeoutK,
			func(i interface{}) {
				sc.readTimeout = durationE(i, fe)
			},
		},
		{
			writeTimeoutK,
			func(i interface{}) {
				sc.writeTimeout = durationE(i, fe)
			},
		},
		{
			addrK,
			func(i interface{}) {
				sc.addr = stringE(i, fe)
			},
		},
		{
			certK,
			func(i interface{}) {
				sc.certFl = stringE(i, fe)
			},
		},
		{
			keyK,
			func(i interface{}) {
				sc.keyFl = stringE(i, fe)
			},
		},
		{
			maxConnIPK,
			func(i interface{}) {
				sc.maxConnIP = intE(i, fe)
			},
		},
		{
			maxReqConnK,
			func(i interface{}) {
				sc.maxReqConn = intE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (p *srvConf) toMap() (i interface{}) {
	mp := map[string]interface{}{
		fastOrStdK:    p.fastOrStd,
		readTimeoutK:  p.readTimeout.String(),
		writeTimeoutK: p.writeTimeout.String(),
		addrK:         p.addr,
	}
	if p.fastOrStd {
		mp[maxConnIPK] = p.maxConnIP
		mp[maxReqConnK] = p.maxReqConn
	}
	if !p.proxyOrIface {
		mp[certK] = p.certFl
		mp[keyK] = p.keyFl
	}
	i = mp
	return
}
