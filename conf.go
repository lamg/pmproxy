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
	"github.com/lamg/viper"
	"github.com/spf13/cast"
	"net/url"
	"os"
	"path"
	"sync"
	"time"
)

type cmd struct {
	Cmd        string                 `json: "cmd"`
	User       string                 `json: "user"`
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
	lg          *logger
	res         *resources
	cm          *connMng
	cr          *crypt

	proxy *srvConf
	iface *srvConf
}

func newConf() (c *conf, e error) {
	c, e = newConfWith(viperWithDisk)
	return
}

func newConfWith(fileInit func() error) (c *conf, e error) {
	// read ip matchers
	// read user information provider
	// read consumption restrictors
	// read rules
	// read admins
	// read logger
	// get searializers (c.mappers)
	// TODO it will initialize resources and then every
	// consR and ipMatcher will be passed to resources.add
	c = &conf{
		iu:         &ipUserS{mäp: new(sync.Map)},
		managerKFs: new(sync.Map),
		matchers:   new(sync.Map),
		consRs:     new(sync.Map),
		mappers:    new(sync.Map),
		userDBs:    new(sync.Map),
		ipGroups:   new(sync.Map),
	}
	fs := []func(){
		func() {
			c.setDefaults()
			e = fileInit()
		},
		func() { e = c.readProxyConf() },
		func() { e = c.readIfaceConf() },
		func() {
			c.admins = viper.GetStringSlice(adminsK)
			e = c.initUserDBs()
		},
		func() { e = c.initSessionIPMs() },
		func() { e = c.initDwnConsRs() },
		func() { e = c.initGroupIPMs() },
		func() { e = c.initLogger() },
		func() { e = c.initResources() },
		func() { e = c.initConnMng() },
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func viperWithDisk() (e error) {
	viper.SetConfigFile(path.Join(home(),
		homeConfigDir, configFile))
	e = viper.ReadInConfig()
	if e != nil {
		e = genConfig()
	}
	return
}

func genConfig() (e error) {
	var dir string
	fs := []func(){
		func() {
			dirs := []string{
				mainConfigDir,
				path.Join(home(), homeConfigDir),
			}
			ib := func(i int) (b bool) {
				e = os.MkdirAll(dirs[i], os.ModeDir|os.ModePerm)
				b = e == nil
				return
			}
			ok, n := bLnSrch(ib, len(dirs))
			if ok {
				dir = dirs[n]
			}
		},
		func() {
			fl := path.Join(dir, configFile)
			e = viper.WriteConfigAs(fl)
			viper.SetConfigFile(fl)
		},
		func() {
			key := path.Join(dir, defaultSrvKey)
			cert := path.Join(dir, defaultSrvCert)
			e = genCert(defaultHost, key, cert)
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func (c *conf) setDefaults() {
	viper.SetKeysCaseSensitive(true)
	viper.SetDefault(compatible02K, true)
	viper.SetDefault(proxyConfK, map[string]interface{}{
		fastOrStdK:    false,
		readTimeoutK:  30 * time.Second,
		writeTimeoutK: 40 * time.Second,
		addrK:         ":8080",
	})
	viper.SetDefault(ifaceConfK, map[string]interface{}{
		fastOrStdK:    false,
		readTimeoutK:  10 * time.Second,
		writeTimeoutK: 15 * time.Second,
		addrK:         ":4443",
		certK:         defaultSrvCert,
		keyK:          defaultSrvKey,
	})
}

func (c *conf) readProxyConf() (e error) {
	i := viper.Get(proxyConfK)
	c.proxy, e = readSrvConf(i)
	if e != nil {
		s := e.Error()
		if s == noKey(certK).Error() || s == noKey(keyK).Error() {
			e = nil
		}
	}
	return
}

func (c *conf) readIfaceConf() (e error) {
	i := viper.Get(ifaceConfK)
	c.iface, e = readSrvConf(i)
	return
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
	c.sliceMap(userDBK, fm, func(d error) { e = d },
		func() bool { return e == nil })
	return
}

func (c *conf) initSessionIPMs() (e error) {
	// c.initUsrDBs()
	fm := func(i interface{}) {
	}
	c.cr, e = newCrypt()
	if e == nil {
		c.sliceMap(
			sessionIPMK,
			fm,
			func(d error) { e = d },
			func() bool { return e == nil },
		)
	}
	return
}

func (c *conf) initDwnConsRs() (e error) {
	// c.initUserDBs()
	fm := func(i interface{}) {
	}
	c.sliceMap(dwnConsRK, fm, func(d error) { e = d },
		func() bool { return e == nil })
	return
}

func (c *conf) userGroups(name string) (
	g func(string) ([]string, error),
	ok bool) {
	v, ok := c.userDBs.Load(name)
	if ok {
		g = v.(*userDB).userGroups
	}
	return
}

func (c *conf) initGroupIPMs() (e error) {
	// c.initUserDBs()
	fm := func(i interface{}) {
		gipm := new(groupIPM)
		e = gipm.fromMap(i)
		if e == nil {
			v, ok := c.userDBs.Load(gipm.userGroupN)
			if ok {
				gipm.userGroup = v.(*userDB).userGroups
				c.managerKFs.Store(gipm.name, gipm.managerKF)
				c.mappers.Store(gipm.name, gipm.toMap)
				c.matchers.Store(gipm.name, gipm.match)
			} else {
				e = noKey(gipm.userGroupN)
			}
		}
	}
	c.sliceMap(groupIPMK, fm, func(d error) { e = d },
		func() bool { return e == nil })
	return
}

func (c *conf) initLogger() (e error) {
	c.lg, e = newLogger(c.strïng(loggerAddrK))
	return
}

func (c *conf) initResources() (e error) {
	v := viper.Get(resourcesK)
	if v != nil {
		c.res = new(resources)
		// TODO
		//e = c.rls.fromMap(v)
		//c.managerKFs.Store(rulesK, c.rls.managerKF)
		//c.rls.ipm = func(name string) (m ipMatcher, ok bool) {
		//	v, ok := c.matchers.Load(name)
		//	if ok {
		//		m = v.(ipMatcher)
		//	}
		//	return
		//}
		//c.mappers.Store(rulesK, c.rls.toMap)
	}
	return
}

func (c *conf) initConnMng() (e error) {
	// c.initRules()
	c.cm = new(connMng)
	v := viper.Get(connMngK)
	e = c.cm.fromMap(v)
	dl := &dialer{
		consRF: func(name string) (cr *consR, ok bool) {
			v, ok := c.consRs.Load(name)
			if ok {
				cr = v.(*consR)
			}
			return
		},
		timeout: viper.GetDuration(timeoutK),
	}
	c.cm.direct = dl.dialContext
	c.cm.ctxVal = func(ctx context.Context, meth, ürl,
		addr string, t time.Time) (nctx context.Context) {
		spec := c.res.match(ürl, addr, t)
		c.lg.log(meth, ürl, spec.ip, spec.user, t)
		nctx = context.WithValue(ctx, specK, spec)
		return
	}
	c.cm.proxyF = func(meth, ürl, addr string,
		t time.Time) (r *url.URL, e error) {
		spec := c.res.match(ürl, addr, t)
		r = spec.proxyURL
		return
	}
	c.mappers.Store(connMngK, c.cm.toMap)
	return
}

func (c *conf) manager(m *cmd) {
	m.User, _ = c.iu.get(m.RemoteAddr)
	m.IsAdmin, _ = bLnSrch(
		func(i int) bool {
			return c.admins[i] == m.User
		},
		len(c.admins),
	)
	v, ok := c.managerKFs.Load(m.Manager)
	var kf []kFunc
	if ok {
		mkf := v.(func(*cmd) []kFunc)
		kf = mkf(m)
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
		exF(kf, m.Cmd, func(d error) { m.e = d })
	} else {
		m.e = noKey(m.Manager)
	}
	return
}

func (c *conf) get(key string) (v interface{}) {
	v = viper.Get(key)
	return
}

func (c *conf) sliceE(key string) (sl []interface{},
	e error) {
	v := c.get(key)
	if v != nil {
		sl, e = cast.ToSliceE(v)
	}
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

func (c *conf) configPath() (dir string) {
	dir = path.Dir(viper.ConfigFileUsed())
	return
}

func (c *conf) sliceMap(key string, fm func(interface{}),
	fe func(error), bf func() bool) {
	vs, e := c.sliceE(key)
	if e == nil {
		inf := func(i int) (b bool) {
			fm(vs[i])
			b = bf()
			return
		}
		trueForall(inf, len(vs))
	} else {
		fe(e)
	}
	return
}
