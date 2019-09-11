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
	"github.com/lamg/proxy"
	"github.com/pelletier/go-toml"
	"github.com/spf13/afero"
	"os"
	"path"
	"time"
)

const (
	defConfDir = ".config/pmproxy"
	confFile   = "managers.toml"
)

func ConfPath() (file, dir string, e error) {
	home, e := os.UserHomeDir()
	dir = path.Join(home, defConfDir)
	file = path.Join(dir, confFile)
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
	var confFullDir, confPath string
	var bs []byte
	c := new(conf)
	var m *manager
	f := []func(){
		func() { confPath, confFullDir, e = ConfPath() },
		func() {
			bs, e = afero.ReadFile(fs, confPath)
		},
		func() { e = toml.Unmarshal(bs, c) },
		func() {
			// rules
			// sessionIPM needs ipUserMng, AdDB or MapDB, cryptMng
			//    (sessionIPM.Name must match a AdDB.Name or MapDB.Name)
			// adms needs sessionIPM
			// dwnConsR needs sessionIPM, AdDB or MapDB
			m = newManager()
			if c.SessionIPM != nil {
				m.mngs.Store(c.SessionIPM.Name, c.SessionIPM.exec)
				m.mngs.Store(ipUserMng, newIpUser().exec)
				if c.AdDB != nil {
					m.mngs.Store(c.AdDB.Name, c.AdDB.exec)
				} else if c.MapDB != nil {
					m.mngs.Store(c.MapDB.Name, c.MapDB.exec)
				} else {
					e = fmt.Errorf("SessionIPM ≠ nil ∧" +
						" AdDB = nil ∧ MapDB = nil")
				}
				if e == nil {
					var cr *crypt
					cr, e = newCrypt(c.JWTExpiration)
					if e == nil {
						m.mngs.Store(cryptMng, cr.exec)
					}
				}
			}
		},
		func() {
			if c.DwnConsR != nil {
				if c.AdDB != nil {
					m.mngs.Store(c.AdDB.Name, c.AdDB.exec)
				} else if c.MapDB != nil {
					m.mngs.Store(c.MapDB.Name, c.MapDB.exec)
				} else if c.SessionIPM != nil {
					e = fmt.Errorf("DwnConsR ≠ nil ∧" +
						" AdDB = nil ∧ MapDB = nil")
				}
			}
		},
		func() {
			if c.SessionIPM == nil && c.DwnConsR != nil {
				e = fmt.Errorf("DwnConsR ≠ nil ∧ SessionIPM = nil ")
			} else if c.DwnConsR != nil {
				e = c.DwnConsR.init(fs, confFullDir)
			}
		},
		func() {
			m.mngs.Store(c.DwnConsR.Name, c.DwnConsR.exec)
		},
		func() {
			var rs *rules
			rs, e = newRules(c.Rules)
			if e == nil {
				m.mngs.Store(RulesK, rs.exec)
			} else {
				m.mngs.Store(RulesK, func(c *Cmd) {
					c.Ok, c.consR = true, make([]string, 0)
				})
			}
		},
		func() {
			m.mngs.Store(connectionsMng, newConnections().exec)
			cmdChan = m.exec
			ctl = func(o *proxy.Operation) (r *proxy.Result) {
				c := &Cmd{
					Manager:   connectionsMng,
					Cmd:       HandleConn,
					Operation: o,
					Result:    new(proxy.Result),
					IP:        o.IP,
					Uint64:    uint64(o.Amount),
				}
				cmdChan(c)
				r = c.Result
				return
			}
			persist = func() (x error) {
				var bs []byte
				g := []func(){
					func() { bs, x = toml.Marshal(c) },
					func() { x = afero.WriteFile(fs, confFile, bs, 0644) },
					func() {
						c.DwnConsR.persist()
					},
				}
				alg.TrueFF(g, func() bool { return x == nil })
				return
			}
		},
	}
	if !alg.TrueFF(f, func() bool { return e == nil }) {
		e = fmt.Errorf("Loading configuration: %w", e)
	}
	return
}

type conf struct {
	JWTExpiration time.Duration `toml:"jwtExpiration"`
	Admins        []string      `toml:"admins"`
	DwnConsR      *dwnConsR     `toml:"dwnConsR"`
	AdDB          *adDB         `toml:"adDB"`
	MapDB         *mapDB        `toml:"mapDB"`
	ParentProxy   string        `toml:"parentProxy"`
	NetIface      string        `toml:"netIface"`
	RangeIPM      *rangeIPM     `toml:"rangeIPM"`
	Rules         string        `toml:"rules" default:"true"`
	SessionIPM    *sessionIPM   `toml:"sessionIPM"`
	SyslogAddr    string        `toml:"syslogAddr"`
}
