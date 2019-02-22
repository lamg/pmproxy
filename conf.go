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
	"context"
	"encoding/json"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"sync"
	"time"
)

type manager func(*cmd)
type managerKF func(*cmd) []kFunc

type cmd struct {
	Cmd        string                 `json: "cmd"`
	Prop       string                 `json: "prop"`
	Manager    string                 `json: "manager"`
	RemoteAddr string                 `json: "remoteAddr"`
	Secret     string                 `json: "secret"`
	IsAdmin    bool                   `json: "isAdmin"`
	Cred       *credentials           `json: "cred"`
	String     string                 `json: "string"`
	Uint64     uint64                 `json: "uint64"`
	Pos        []int                  `json: "pos"`
	Object     map[string]interface{} `json: "object"`
	comp02     bool                   //compatible with v0.2
	bs         []byte
	e          error
}

type credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type ipMatcher func(string) bool

type conf struct {
	admins      []string
	staticFPath string
	iu          *ipUserS
	managerKFs  *sync.Map
	ipGroups    *sync.Map
	matchers    *sync.Map
	consRs      *sync.Map
	mappers     *sync.Map
	userDBs     *sync.Map
	ipQuotas    *sync.Map
	lg          *logger
	rls         *rules
	cm          *connMng
	cr          *crypt
}

func newConf() (c *conf, e error) {
	// read ip matchers
	// read user information provider
	// read consumption restrictors
	// read rules
	// read admins
	// read logger
	// get searializers (c.mappers)
	viper.SetConfigName("pmproxy")
	viper.SetConfigType("toml")
	viper.AddConfigPath("$HOME/.config")
	viper.AddConfigPath("/etc")
	c = &conf{
		iu:         &ipUserS{mäp: new(sync.Map)},
		managerKFs: new(sync.Map),
		matchers:   new(sync.Map),
		consRs:     new(sync.Map),
		mappers:    new(sync.Map),
		userDBs:    new(sync.Map),
		ipQuotas:   new(sync.Map),
	}
	fs := []func(){
		func() {
			e = viper.ReadInConfig()
			if e != nil {
				c.setDefaults()
				home := os.Getenv("HOME")
				e = viper.WriteConfigAs(
					path.Join(home, ".config/pmproxy.toml"))
			}
		},
		func() {
			c.admins = viper.GetStringSlice(adminsK)
			e = c.initUserDBs()
		},
		func() { e = c.initSessionIPMs() },
		func() { e = c.initIPQuotas() },
		func() { e = c.initDwnConsRs() },
		func() { e = c.initUserInfos() },
		func() { e = c.initGroupIPMs() },
		func() { e = c.initLogger() },
		func() { e = c.initRules() },
		func() { e = c.initConnMng() },
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func (c *conf) setDefaults() {
	// TODO
	// set default userDB
	viper.Set(userDBK, []map[string]interface{}{
		{
			nameK:    defaultUserDB,
			adOrMapK: false,
			paramsK: map[string]interface{}{
				userPassK: map[string]interface{}{
					user0: pass0,
				},
				userGroupsK: map[string][]string{
					user0: {group0},
				},
			},
		},
	})
	// set default matchers
	viper.Set(sessionIPMK, []map[string]interface{}{
		{
			nameK:     defaultSessionIPM,
			authNameK: defaultUserDB,
		},
	})
	// set default consR
	viper.Set(dwnConsRK, []map[string]interface{}{
		{
			nameK:       defaultDwnConsR,
			ipQuotaK:    defaultIPQuota,
			lastResetK:  time.Now(),
			resetCycleK: time.Duration(24 * time.Hour).String(),
		},
	})
	// set default rules
	viper.Set(rulesK, []map[string]interface{}{
		{
			posK: 0,
			reqK: map[string]interface{}{
				unitK: true,
				ipmK:  defaultSessionIPM,
				string(specK): map[string]interface{}{
					ifaceK: defaultIface,
					consRK: defaultDwnConsR,
				},
			},
		},
	})
	viper.Set(adminsK, []string{user0})
	// …
}

func (c *conf) initUserDBs() (e error) {
	// def.(maps in c)
	fm := func(i interface{}) {
		udb := new(userDB)
		e = udb.fromMap(i)
		if e == nil {
			c.managerKFs.Store(udb.name, udb.managerKF)
			c.mappers.Store(udb.name, udb.toMap)
			c.userDBs.Store(udb.name, udb)
		}
	}
	c.sliceMap(userDBK, fm, func() bool { return e == nil })
	return
}

func (c *conf) initSessionIPMs() (e error) {
	// c.initUsrDBs() /\ def.(maps in c)
	fm := func(i interface{}) {
		sm := &sessionIPM{
			iu: c.iu,
			cr: c.cr,
		}
		e = sm.fromMap(i)
		if e == nil {
			sm.nameAuth = c.authenticator
			c.managerKFs.Store(sm.name, sm.managerKF)
			c.matchers.Store(sm.name, sm.match)
			c.mappers.Store(sm.name, sm.toMap)
		}
	}
	e = c.sliceMap(sessionIPMK, fm,
		func() bool { return e == nil })
	return
}

func (c *conf) authenticator(name string) (a auth,
	ok bool) {
	v, ok := c.userDBs.Load(name)
	if ok {
		a = v.(*userDB).ath
	}
	return
}

func (c *conf) initIPQuotas() (e error) {
	// def.(maps in c, c.iu) /\ c.initUserDBs()
	fm := func(i interface{}) {
		ipq := new(ipQuotaS)
		e = ipq.fromMap(i)
		if e == nil {
			ipg := &ipGroupS{
				ipUser:     c.iu.get,
				userGroup:  c.userGroup,
				userGroupN: ipq.name,
			}
			c.ipGroups.Store(ipg.userGroupN, ipg)
			ipq.ipg = ipg.get
			c.managerKFs.Store(ipq.name, ipq.managerKF)
			c.ipQuotas.Store(ipq.name, ipq.get)
			c.mappers.Store(ipq.name, ipq.toMap)
		}
	}
	c.sliceMap(ipQuotaK, fm, func() bool { return e == nil })
	return
}

func (c *conf) initDwnConsRs() (e error) {
	// c.initIPQuotas() /\ def.(maps in c)
	fm := func(i interface{}) {
		dw := new(dwnConsR)
		e = dw.fromMap(i)
		if e == nil {
			v, ok := c.ipQuotas.Load(dw.ipQuotaN)
			if ok {
				dw.ipq = v.(*ipQuotaS).get
			}
			dw.mapWriter = func(mp map[string]uint64) {
				var ppath string
				var bs []byte
				var e error
				fs := []func(){
					func() { ppath = c.strïng(persistPathK) },
					func() { bs, e = json.Marshal(mp) },
					func() {
						ioutil.WriteFile(
							path.Join(ppath, dw.name+".json"),
							bs,
							os.ModePerm,
						)
					},
				}
				trueFF(fs,
					func() bool { return ppath != "" && e == nil })
			}
			c.managerKFs.Store(dw.name, dw.managerKF)
			c.consRs.Store(dw.name, dw.consR())
			c.mappers.Store(dw.name, dw.toMap)
		}
	}
	e = c.sliceMap(dwnConsRK, fm,
		func() bool { return e == nil })
	return
}

func (c *conf) userGroup(name string) (g userGroup,
	ok bool) {
	v, ok := c.userDBs.Load(name)
	if ok {
		g = v.(*userDB).grp
	}
	return
}

func (c *conf) initUserInfos() (e error) {
	// notice that there are several userDB
	// forall of them a userInfo should exist
	// for each userDB, for each ipQuota with the same
	// userDB
	// def.(c.admins, c.iu, maps in c) /\ c.initUserDBs()
	isAdm := func(user string) (v bool) {
		v, _ = bLnSrch(func(i int) bool {
			return c.admins[i] == user
		},
			len(c.admins),
		)
		return
	}
	c.ipQuotas.Range(func(k, v interface{}) (ok bool) {
		udbName := k.(string)
		uv, ok := c.userDBs.Load(udbName)
		if ok {
			udb := uv.(*userDB)
			ui := &userInfo{
				iu:       c.iu.get,
				userName: udb.unm,
				quota:    v.(ipQuota),
				isAdm:    isAdm,
			}
			c.managerKFs.Store(udbName+infoK, ui.managerKF)
		}
		ok = true
		return
	})
	return
}

func (c *conf) initGroupIPMs() (e error) {
	// def.(maps in c, c.iu) /\ c.initUserDBs()
	fm := func(i interface{}) {
		gipm := new(groupIPM)
		e = gipm.fromMap(i)
		if e == nil {
			v, ok := c.ipGroups.Load(gipm.ipGroupN)
			if ok {
				gipm.ipg = v.(*ipGroupS).get
				c.managerKFs.Store(gipm.name, gipm.managerKF)
				c.mappers.Store(gipm.name, gipm.toMap)
				c.matchers.Store(gipm.name, gipm.match)
			} else {
				e = noKey(gipm.ipGroupN)
			}
		}
	}
	c.sliceMap(groupIPMK, fm,
		func() bool { return e == nil })
	return
}

func (c *conf) initLogger() (e error) {
	c.lg, e = newLogger(c.strïng(loggerAddrK))
	return
}

func (c *conf) initRules() (e error) {
	// c.initSessionIPMs() /\ c.initGroupIPMs()
	// /\ c.initDwnConsRs()
	v := viper.Get(rulesK)
	c.rls = new(rules)
	e = c.rls.fromMap(v)
	c.managerKFs.Store(rulesK, c.rls.managerKF)
	c.rls.ipm = func(name string) (m ipMatcher, ok bool) {
		v, ok := c.matchers.Load(name)
		if ok {
			m = v.(ipMatcher)
		}
		return
	}
	c.mappers.Store(rulesK, c.rls.toMap)
	return
}

func (c *conf) initConnMng() (e error) {
	// c.initRules()
	c.cm = new(connMng)
	v := viper.Get(connMngK)
	e = c.cm.fromMap(v)
	dl := newDialer(
		func(name string) (cr *consR, ok bool) {
			v, ok := c.consRs.Load(name)
			if ok {
				cr = v.(*consR)
			}
			return
		},
		c.lg,
	)
	c.cm.direct = dl.dialContext
	c.cm.ctxVal = func(ctx context.Context, meth, ürl,
		addr string, t time.Time) (nctx context.Context) {
		spec := c.rls.match(meth, ürl, addr, t)
		nctx = context.WithValue(ctx, specK, spec)
		return
	}
	c.cm.proxyF = func(meth, ürl, addr string,
		t time.Time) (r *url.URL, e error) {
		spec := c.rls.match(meth, ürl, addr, t)
		r = spec.proxyURL
		return
	}
	c.mappers.Store(connMngK, c.cm.toMap)
	return
}

func (c *conf) manager(m *cmd) {
	musr, ok := c.iu.get(m.RemoteAddr)
	m.IsAdmin, _ = bLnSrch(
		func(i int) bool {
			return c.admins[i] == musr
		},
		len(c.admins),
	)
	var v interface{}
	if ok {
		v, ok = c.managerKFs.Load(m.Manager)
	}
	var kf []kFunc
	if ok {
		kf = v.(managerKF)(m)
		kf = append(kf,
			kFunc{skip, func() {}},
			kFunc{
				showAll,
				func() {
					mngs := make([]string, 0)
					c.managerKFs.Range(
						func(k, v interface{}) (ok bool) {
							mngs = append(mngs, k.(string))
							ok = true
							return
						},
					)
					m.bs, m.e = json.Marshal(&mngs)
				},
			},
		)
	}
	exF(kf, m.Cmd, func(d error) { m.e = d })
	return
}

func (c *conf) get(key string) (v interface{}) {
	v = viper.Get(key)
	return
}

func (c *conf) sliceE(key string) (sl []interface{},
	e error) {
	sl, e = cast.ToSliceE(c.get(key))
	return
}

func (c *conf) böol(key string) (b bool) {
	b = viper.GetBool(key)
	return
}

func (c *conf) strïng(key string) (s string) {
	s = viper.GetString(key)
	return
}

func (c *conf) configPath(file string) (fpath string) {
	cfl := viper.ConfigFileUsed()
	fpath = path.Join(path.Dir(cfl), file)
	return
}

func (c *conf) sliceMap(key string, fm func(interface{}),
	bf func() bool) (e error) {
	vs, e := c.sliceE(key)
	if e == nil {
		inf := func(i int) (b bool) {
			fm(vs[i])
			b = bf()
			return
		}
		trueForall(inf, len(vs))
	}
	return
}
