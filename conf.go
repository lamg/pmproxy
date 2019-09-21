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
	alg "github.com/lamg/algorithms"
	"github.com/pelletier/go-toml"
	"github.com/spf13/afero"
	"net"
	"os"
	"path"
	"time"
)

const (
	confDir  = ".config/pmproxy"
	confFile = "server.toml"
)

func load(fs afero.Fs) (p *pmproxyConf, e error) {
	p = new(pmproxyConf)
	var exCrt, exKey bool
	var certFl, keyFl, host, home string
	var bs []byte
	f := []func(){
		func() { home, e = os.UserHomeDir() },
		func() {
			confPath := path.Join(home, confDir, confFile)
			bs, e = afero.ReadFile(fs, confPath)
		},
		func() { e = toml.Unmarshal(bs, p) },
		func() {
			certFl = path.Join(home, confDir, p.Api.HTTPSCert)
			p.Api.HTTPSCert = certFl
			exCrt, e = afero.Exists(fs, certFl)
		},
		func() {
			keyFl = path.Join(home, confDir, p.Api.HTTPSKey)
			p.Api.HTTPSKey = keyFl
			exKey, e = afero.Exists(fs, keyFl)
		},
		func() {
			host, _, e = net.SplitHostPort(p.Api.Server.Addr)
		},
		func() {
			if !exCrt || !exKey {
				e = genCert(host, keyFl, certFl, fs)
			}
		},
	}
	alg.TrueFF(f, func() bool { return e == nil })
	return
}

type pmproxyConf struct {
	Api   *apiConf   `toml:"api"`
	Proxy *proxyConf `toml:"proxy"`
}

type apiConf struct {
	HTTPSCert         string        `toml:"httpsCert"`
	HTTPSKey          string        `toml:"httpsKey"`
	WebStaticFilesDir string        `toml:"webStaticFilesDir"`
	PersistInterval   time.Duration `toml:"persistInterval"`
	Server            *srvConf      `toml:"server"`
}

type proxyConf struct {
	DialTimeout time.Duration `toml:"dialTimeout"`
	Server      *srvConf      `toml:"server"`
}

type srvConf struct {
	ReadTimeout  time.Duration `toml:"readTimeout"`
	WriteTimeout time.Duration `toml:"writeTimeout"`
	Addr         string        `toml:"addr"`
	FastOrStd    bool          `toml:"fastOrStd"`
}
