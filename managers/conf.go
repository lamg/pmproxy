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
			e = initParentProxy(c.ParentProxy, m)
		},
		func() { initNetIface(c.NetIface, m) },
		func() { e = initRangeIPM(c.RangeIPM, m) },
		func() { e = initSessionIPM(c, m) },
		func() { e = initDwnConsR(c, m) },
		func() { initAdmins(c, m) },
		func() {
			if len(c.SessionIPM) == 0 && len(c.DwnConsR) != 0 {
				e = &DependencyErr{
					name:   c.DwnConsR[0].Name,
					tÿpe:   DwnConsRK,
					absent: []string{SessionIPMK},
				}
			} else if len(c.DwnConsR) != 0 {
				alg.BLnSrch(
					func(i int) bool {
						e = c.DwnConsR[i].init(fs, confFullDir)
						return e != nil
					},
					len(c.DwnConsR),
				)
			}
		},
		func() { initTimeSpan(c.TimeSpan, m, c.now) },
		func() { initGroupIPM(c.GroupIPM, m) },
		func() { e = initRulesAndConns(c, m) },
		func() {
			cmdChan = m.exec
			dlr = &Dialer{cf: c, cmdf: cmdChan, Dialer: NetDialerF}
			if c.DwnConsR != nil {
				persist = func() (err error) {
					alg.Forall(
						func(i int) { c.DwnConsR[i].persist() },
						len(c.DwnConsR),
					)
					return
				}
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
	JWTExpiration time.Duration    `toml:"jwtExpiration"`
	Admins        []string         `toml:"admins"`
	DwnConsR      []*DwnConsR      `toml:"dwnConsR"`
	GroupIPM      []*groupIPM      `toml:"groupIPM"`
	AdDB          *adDB            `toml:"adDB"`
	MapDB         *mapDB           `toml:"mapDB"`
	ParentProxy   []*proxyURLMng   `toml:"parentProxy"`
	NetIface      []*proxyIfaceMng `toml:"netIface"`
	RangeIPM      []*rangeIPM      `toml:"rangeIPM"`
	Rules         string           `toml:"rules" default:"true"`
	SessionIPM    []*sessionIPM    `toml:"sessionIPM"`
	SyslogAddr    string           `toml:"syslogAddr"`
	TimeSpan      []*span          `toml:"timeSpan"`

	now func() time.Time
}

func initRangeIPM(rs []*rangeIPM, m *manager) (e error) {
	ib := func(i int) bool {
		e = rs[i].init()
		return e != nil
	}
	alg.BLnSrch(ib, len(rs))
	if e == nil {
		inf := func(i int) { m.mngs.Store(rs[i].Name, rs[i].exec) }
		alg.Forall(inf, len(rs))
	}
	return
}

func initGroupIPM(gs []*groupIPM, m *manager) {
	alg.Forall(
		func(i int) { m.mngs.Store(gs[i].Name, gs[i].exec) }, len(gs),
	)
}

func initTimeSpan(ts []*span, m *manager, now func() time.Time) {
	pths := make([]mngPath, len(ts))
	alg.Forall(
		func(i int) {
			ts[i].now = now
			m.mngs.Store(ts[i].Name, ts[i].exec)
			pths[i] = mngPath{
				cmd:  Match,
				name: ts[i].Name,
				mngs: []mngPath{{cmd: Match, name: ts[i].Name}},
			}
		},
		len(ts),
	)
	m.paths = append(m.paths, pths...)
}

func initParentProxy(ps []*proxyURLMng, m *manager) (e error) {
	ib := func(i int) bool {
		e = ps[i].init()
		return e != nil
	}
	alg.BLnSrch(ib, len(ps))
	if e == nil {
		pths := make([]mngPath, len(ps))
		inf := func(i int) {
			m.mngs.Store(ps[i].Name, ps[i].exec)
			pths[i] = mngPath{
				name: ps[i].Name,
				cmd:  Match,
				mngs: []mngPath{{cmd: Match, name: ps[i].Name}},
			}
		}
		alg.Forall(inf, len(ps))
		m.paths = append(m.paths, pths...)
	}
	return
}

func initNetIface(ns []*proxyIfaceMng, m *manager) {
	pths := make([]mngPath, len(ns))
	inf := func(i int) {
		m.mngs.Store(ns[i].Name, ns[i].exec)
		pths[i] = mngPath{
			name: ns[i].Name,
			cmd:  Match,
			mngs: []mngPath{{cmd: Match, name: ns[i].Name}},
		}
	}
	alg.Forall(inf, len(ns))
	m.paths = append(m.paths, pths...)
}

func initSessionIPM(c *conf, m *manager) (e error) {
	// rules
	// sessionIPM needs ipUserMng, AdDB or MapDB, cryptMng
	//    (sessionIPM.Name must match a AdDB.Name or MapDB.Name)
	// adms needs sessionIPM
	// dwnConsR needs sessionIPM, AdDB or MapDB
	m.mngs.Store(ipUserMng, newIpUser().exec)
	if c.AdDB != nil {
		m.mngs.Store(c.AdDB.Name, c.AdDB.exec)
	}
	if c.MapDB != nil {
		m.mngs.Store(c.MapDB.Name, c.MapDB.exec)
	}
	cr, e := newCrypt(c.JWTExpiration)
	if e == nil {
		m.mngs.Store(cryptMng, cr.exec)
	}
	alg.BLnSrch(
		func(i int) bool {
			m.mngs.Store(c.SessionIPM[i].Name, c.SessionIPM[i].exec)
			if (c.AdDB == nil && c.MapDB == nil) ||
				((c.AdDB != nil && c.AdDB.Name != c.SessionIPM[i].Auth) &&
					(c.MapDB != nil &&
						c.MapDB.Name != c.SessionIPM[i].Auth)) ||
				(c.AdDB != nil && c.MapDB != nil &&
					c.AdDB.Name == c.MapDB.Name) {
				e = &DependencyErr{
					name:   c.SessionIPM[i].Name,
					tÿpe:   SessionIPMK,
					absent: []string{"adDB", "mapDB"},
				}
			}
			if e == nil {
				smPaths := c.SessionIPM[i].paths()
				m.paths = append(m.paths, smPaths...)
			}
			return e != nil
		},
		len(c.SessionIPM),
	)
	return
}

func initDwnConsR(c *conf, m *manager) (e error) {
	if len(c.DwnConsR) != 0 {
		if c.AdDB != nil {
			m.mngs.Store(c.AdDB.Name, c.AdDB.exec)
		} else if c.MapDB != nil {
			m.mngs.Store(c.MapDB.Name, c.MapDB.exec)
		} else if len(c.SessionIPM) != 0 {
			e = &DependencyErr{
				name:   c.DwnConsR[0].Name,
				tÿpe:   DwnConsRK,
				absent: []string{"mapDB", "adDB"},
			}
		}
		if e == nil {
			alg.Forall(
				func(i int) {
					m.mngs.Store(c.DwnConsR[i].Name, c.DwnConsR[i].exec)
				},
				len(c.DwnConsR),
			)
			alg.Forall(
				func(i int) {
					ds := c.DwnConsR[i].paths()
					m.paths = append(m.paths, ds...)
					c.DwnConsR[i].now = c.now
				},
				len(c.DwnConsR),
			)
		}
	}
	return
}

func initRulesAndConns(c *conf, m *manager) (e error) {
	var rs *rules
	rs, e = newRules(c.Rules)
	if e == nil {
		m.mngs.Store(RulesK, rs.exec)
		sm, dw, ipm, ps, ns :=
			initStrSlice(
				func() int { return len(c.SessionIPM) },
				func(i int) string { return c.SessionIPM[i].Name }),
			initStrSlice(
				func() int { return len(c.DwnConsR) },
				func(i int) string { return c.DwnConsR[i].Name }),
			initStrSlice(
				func() int { return len(c.RangeIPM) },
				func(i int) string { return c.RangeIPM[i].Name }),
			initStrSlice(
				func() int { return len(c.ParentProxy) },
				func(i int) string { return c.ParentProxy[i].Name }),
			initStrSlice(
				func() int { return len(c.NetIface) },
				func(i int) string { return c.NetIface[i].Name })
		ms := rs.paths(sm, dw, ipm, ps, ns, c.GroupIPM)
		m.paths = append(m.paths, ms...)
		n := 0
		if ms[n].cmd == Discover {
			n = 1
		}
		initConnMng(c, m, ms[n].mngs)
	} else {
		m.mngs.Store(RulesK, func(c *Cmd) {
			c.ok, c.consR = true, make([]string, 0)
		})
	}
	return
}

func initStrSlice(length func() int,
	str func(int) string) (r []string) {
	n := length()
	r = make([]string, n)
	alg.Forall(func(i int) { r[i] = str(i) }, n)
	return
}

func initConnMng(c *conf, m *manager, rdeps []mngPath) (e error) {
	cs := &connections{ipRestr: new(sync.Map)}
	cs.logger, e = newLogger(c.SyslogAddr, c.now)
	if e == nil {
		ms := make([]mngPath, len(c.DwnConsR))
		alg.Forall(
			func(i int) {
				ms[i] = mngPath{
					name: c.DwnConsR[i].Name,
					mngs: []mngPath{
						{name: adminsMng, cmd: Protect},
						{name: ipUserMng, cmd: Get},
						{name: c.DwnConsR[i].UserDBN, cmd: Get},
					},
				}
			},
			len(ms),
		)
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
