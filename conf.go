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
// Public License along with PMProxy. If not, see
// <https://www.gnu.org/licenses/>.

package pmproxy

import (
	mng "github.com/lamg/pmproxy/managers"
)

func loadSrvConf(fs afero.Fs) (p *proxyConf, i *apiConf, e error) {
	bs, e := afero.ReadFile(fs, "~/config/pmproxy/conf.toml")
	if e == nil {
		tr, e = toml.LoadBytes(bs)
	}
	if e == nil {
		cmdChan, ctl, e := mng.Load(tr, fs)
		if e == nil {
			it := tr.Get("api").(*toml.Tree)
			i = new(apiConf)
			e = it.Unmarshal(i)
		}
		if e == nil {
			pt := tr.Get("proxy").(*toml.Tree)
			p = new(proxyConf)
			e = pt.Unmarshal(p)
		}
	} else {

	}
	return
}

type apiConf struct {
	HTTPSCert         string        `toml:"httpsCert"`
	HTTPSKey          string        `toml:"httpsKey"`
	WebStaticFilesDir string        `toml:"webStaticFilesDir"`
	PersistInterval   time.Duration `toml:"persistInterval"`
	Server            *srvConf      `toml:"server"`
	cmdChan           mng.CmdF
	persist           func() error
}

type proxyConf struct {
	DialTimeout time.Duration `toml:"dialTimeout"`
	Server      *srvConf      `toml:"server"`
	ctl         proxy.ControlConn
	now         func() time.Time
}

type srvConf struct {
	ReadTimeout  time.Duration `toml:"readTimeout"`
	WriteTimeout time.Duration `toml:"writeTimeout"`
	Addr         string        `toml:"addr"`
	FastOrStd    bool          `toml:"fastOrStd"`
}
