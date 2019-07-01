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

/*
# Configuration

This file loads the main managers: the resource matcher and the connection handler.
*/

import (
	alg "github.com/lamg/algorithms"
	pred "github.com/lamg/predicate"
	"github.com/lamg/proxy"
	"github.com/pelletier/go-toml"
	"github.com/spf13/afero"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	defConfDir = ".config/pmproxy"
	confFile   = "managers.toml"
)

func ConfPath() (r string) {
	home, _ := os.UserHomeDir()
	confFullDir := path.Join(home, defConfDir)
	r = path.Join(confFullDir, confFile)
	return
}

func Load(confDir string, fs afero.Fs) (
	cmdChan CmdF,
	ctl proxy.ConnControl,
	persist func() error,
	e error) {
	if confDir == "" {
		confDir = defConfDir
	}
	var home, confFullDir, confPath string
	var bs []byte
	c := new(conf)
	var m *manager
	f := []func(){
		func() { home, e = os.UserHomeDir() },
		func() {
			confFullDir = path.Join(home, confDir)
			confPath = path.Join(confFullDir, confFile)
			bs, e = afero.ReadFile(fs, confPath)
		},
		func() { e = toml.Unmarshal(bs, c) },
		func() {
			ib := func(i int) (b bool) {
				e = c.DwnConsR[i].init(confFullDir, fs)
				b = e != nil
				return
			}
			alg.BLnSrch(ib, len(c.DwnConsR))
		},
		func() { m, e = newManager(c) },
		func() {
			cmdChan = m.exec
			ctl = func(o *proxy.Operation) (r *proxy.Result) {
				c := &Cmd{
					Manager:   connectionsMng,
					Cmd:       HandleConn,
					Operation: o,
					Result:    new(proxy.Result),
				}
				cmdChan(c)
				r = c.Result
				return
			}
			persist = func() (x error) {
				var bs []byte
				g := []func(){
					func() { bs, x = toml.Marshal(c) },
					func() { x = afero.WriteFile(fs, confPath, bs, 0644) },
					func() {
						inf := func(i int) { x = c.DwnConsR[i].persist() }
						alg.Forall(inf, len(c.DwnConsR))
					},
				}
				alg.TrueFF(g, func() bool { return x == nil })
				return
			}
		},
	}
	alg.TrueFF(f, func() bool { return e == nil })
	return
}

func BasicConf(pth string, fs afero.Fs) (e error) {
	cf := &conf{
		Admins: []string{"pepe"},
	}
	bs, e := toml.Marshal(cf)
	if e == nil {
		e = afero.WriteFile(fs, pth, bs, 0644)
	}
	return
}

type conf struct {
	JWTExpiration time.Duration   `toml:"jwtExpiration"`
	Rule          string          `toml:"rule"`
	Admins        []string        `toml:"admins"`
	DwnConsR      []dwnConsR      `toml:"dwnConsR"`
	BwConsR       []bwConsR       `toml:"bwConsR"`
	AdDB          []adDB          `toml:"adDB"`
	MapDB         []mapDB         `toml:"mapDB"`
	GroupIPM      []groupIPM      `toml:"groupIPM"`
	ProxyIface    []proxyIfaceMng `toml:"proxyIface"`
	ParentProxy   []proxyURLMng   `toml:"parentProxy"`
	RangeIPM      []rangeIPM      `toml:"rangeIPM"`
	SessionIPM    []sessionIPM    `toml:"sessionIPM"`
	// managers which the majority of users will use for
	// handling their connections
	DefaultMngs []string `toml:"defaultMngs"`
}

func newManager(c *conf) (m *manager, e error) {
	m = &manager{mngs: new(sync.Map)}
	iu := newIpUser()
	cr, e := newCrypt(c.JWTExpiration)
	mt := new(matchers)
	fs := []func(){
		func() { mt.rules, e = pred.Parse(strings.NewReader(c.Rule)) },
		func() {
			m.add(connectionsMng, newConnections().exec)
			m.add(ipUserMng, iu.exec)
			m.add(cryptMng, cr.exec)
			m.add(MatchersMng, mt.exec)
		},
	}
	alg.TrueFF(fs, func() bool { return e == nil })
	// TODO
	return
}
