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
	"github.com/pelletier/go-toml"
	"github.com/spf13/afero"
	"net/url"
	"os"
	"path"
	"sync"
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
	dlr *Dialer,
	persist func() error,
	e error,
) {
	if confDir == "" {
		confDir = defConfDir
	}
	var confFullDir, confPath string
	var bs []byte
	c, m := new(conf), newManager()
	f := []func(){
		func() { confPath, confFullDir, e = ConfPath() },
		func() {
			bs, e = afero.ReadFile(fs, confPath)
		},
		func() { e = toml.Unmarshal(bs, c) },
		func() {
			c.now = time.Now
			if c.AdDB != nil {
				c.AdDB.init()
			}
			if c.ParentProxy != "" {
				c.parentProxy, e = url.Parse(c.ParentProxy)
			}
		},
		func() { e = initSessionIPM(c, m) },
		func() { e = initDwnConsR(c, m) },
		func() { initAdmins(c, m) },
		func() {
			if c.SessionIPM == nil && c.DwnConsR != nil {
				e = &DependencyErr{
					name:   c.DwnConsR.Name,
					tÿpe:   DwnConsRK,
					absent: []string{SessionIPMK},
				}
			} else if c.DwnConsR != nil {
				e = c.DwnConsR.init(fs, confFullDir)
			}
		},
		func() {
			m.mngs.Store(c.DwnConsR.Name, c.DwnConsR.exec)
		},
		func() { e = initRulesAndConns(c, m) },
		func() {
			cmdChan = m.exec
			dlr = &Dialer{cf: c, cmdf: cmdChan, Dialer: NetDialerF}
			if c.DwnConsR != nil {
				persist = c.DwnConsR.persist
			} else {
				persist = func() (e error) { return }
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
	DwnConsR      *DwnConsR     `toml:"dwnConsR"`
	AdDB          *adDB         `toml:"adDB"`
	MapDB         *mapDB        `toml:"mapDB"`
	ParentProxy   string        `toml:"parentProxy"`
	NetIface      string        `toml:"netIface"`
	RangeIPM      *rangeIPM     `toml:"rangeIPM"`
	Rules         string        `toml:"rules" default:"true"`
	SessionIPM    *sessionIPM   `toml:"sessionIPM"`
	SyslogAddr    string        `toml:"syslogAddr"`

	parentProxy *url.URL
	now         func() time.Time
}

func initSessionIPM(c *conf, m *manager) (e error) {
	// rules
	// sessionIPM needs ipUserMng, AdDB or MapDB, cryptMng
	//    (sessionIPM.Name must match a AdDB.Name or MapDB.Name)
	// adms needs sessionIPM
	// dwnConsR needs sessionIPM, AdDB or MapDB
	if c.SessionIPM != nil {
		m.mngs.Store(c.SessionIPM.Name, c.SessionIPM.exec)
		m.mngs.Store(ipUserMng, newIpUser().exec)
		if c.AdDB != nil {
			m.mngs.Store(c.AdDB.Name, c.AdDB.exec)
		}
		if c.MapDB != nil {
			m.mngs.Store(c.MapDB.Name, c.MapDB.exec)
		}
		if (c.AdDB == nil && c.MapDB == nil) ||
			(c.AdDB != nil && c.AdDB.Name != c.SessionIPM.Auth) ||
			(c.MapDB != nil && c.MapDB.Name != c.SessionIPM.Auth) {
			e = &DependencyErr{
				name:   c.SessionIPM.Name,
				tÿpe:   SessionIPMK,
				absent: []string{"adDB", "mapDB"},
			}
		}
		if e == nil {
			var cr *crypt
			cr, e = newCrypt(c.JWTExpiration)
			if e == nil {
				m.mngs.Store(cryptMng, cr.exec)
				smPaths := c.SessionIPM.paths()
				m.paths = append(m.paths, smPaths...)
			}
		}
	}
	return
}

func initDwnConsR(c *conf, m *manager) (e error) {
	if c.DwnConsR != nil {
		if c.AdDB != nil {
			m.mngs.Store(c.AdDB.Name, c.AdDB.exec)
		} else if c.MapDB != nil {
			m.mngs.Store(c.MapDB.Name, c.MapDB.exec)
		} else if c.SessionIPM != nil {
			e = &DependencyErr{
				name:   c.DwnConsR.Name,
				tÿpe:   DwnConsRK,
				absent: []string{"mapDB", "adDB"},
			}
		}
		if e == nil {
			ds := c.DwnConsR.paths()
			m.paths = append(m.paths, ds...)
			c.DwnConsR.now = c.now
		}
	}
	return
}

func initRulesAndConns(c *conf, m *manager) (e error) {
	var rs *rules
	rs, e = newRules(c.Rules)
	if e == nil {
		m.mngs.Store(RulesK, rs.exec)
		var sm, dw, ipm string
		if c.SessionIPM != nil {
			sm = c.SessionIPM.Name
		}
		if c.DwnConsR != nil {
			dw = c.DwnConsR.Name
		}
		if c.RangeIPM != nil {
			ipm = c.RangeIPM.Name
		}
		ms := rs.paths(sm, dw, ipm)
		m.paths = append(m.paths, ms...)
		n := 0
		if ms[n].cmd == Discover {
			n = 1
		}
		initConnMng(c, m, ms[n].mngs)
	} else {
		m.mngs.Store(RulesK, func(c *Cmd) {
			c.Ok, c.consR = true, make([]string, 0)
		})
	}
	return
}

func initConnMng(c *conf, m *manager, rdeps []mngPath) (e error) {
	cs := &connections{ipRestr: new(sync.Map)}
	cs.logger, e = newLogger(c.SyslogAddr, c.now)
	if e == nil {
		ms := []mngPath{
			{
				name: c.DwnConsR.Name,
				mngs: []mngPath{
					{name: ipUserMng, cmd: Get},
					{name: c.DwnConsR.UserDBN, cmd: Get},
				},
			},
		}
		cps := connPaths(ms, rdeps)
		m.mngs.Store(connectionsMng, cs.exec)
		m.paths = append(m.paths, cps...)
	}
	return
}

func initAdmins(c *conf, m *manager) {
	adm := &admins{admins: c.Admins}
	m.mngs.Store(adminsMng, adm.exec)
	m.paths = append(m.paths, adm.paths()...)
}
