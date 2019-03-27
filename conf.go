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
	"fmt"
	pred "github.com/lamg/predicate"
	"github.com/lamg/viper"
	"github.com/spf13/cast"
	"net/url"
	"os"
	"path"
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

type conf struct {
	staticFPath string

	lg      *logger
	res     *resources
	cm      *connMng
	proxy   *srvConf
	iface   *srvConf
	waitUpd time.Duration
}

func newConf() (c *conf, e error) {
	c, e = newConfWith(viperWithDisk)
	return
}

func newConfWith(fileInit func() error) (c *conf, e error) {
	c = &conf{}
	fs := []func(){
		func() {
			c.setDefaults()
			e = fileInit()
		},
		func() { e = c.readProxyConf() },
		func() { e = c.readIfaceConf() },
		func() { e = c.initResources() },
		func() { e = c.initLogger() },
		func() { e = c.initConnMng() },
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func (c *conf) update() (e error) {
	// TODO get all configuration and write to disk
	return
}

func (c *conf) initConnMng() (e error) {
	// c.initRules()
	c.cm = new(connMng)
	v := viper.Get(connMngK)
	e = c.cm.fromMap(v)
	dl := &dialer{
		consRF: func(name string) (cr *consR, ok bool) {
			v, ok := c.res.managers.Load(name)
			if ok {
				cr = v.(*manager).consR
				ok = cr != nil
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
	mng := &manager{
		tÿpe:   connMngK,
		mapper: c.cm.toMap,
	}
	c.res.managers.Store(connMngK, mng)
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
	viper.SetDefault(rulesK, pred.TrueStr)
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

func (c *conf) initLogger() (e error) {
	c.lg, e = newLogger(c.strïng(loggerAddrK))
	return
}

func (c *conf) initResources() (e error) {
	fe := func(d error) { e = d }
	var predCf string
	fs := []func(){
		func() {
			v := viper.Get(rulesK)
			predCf = stringE(v, fe)
		},
		func() {
			c.res, e = newResources(predCf, viper.GetStringSlice(adminsK))
		},
		func() {
		},
		func() {
			rs := []string{userDBK, sessionIPMK, dwnConsRK, groupIPMK,
				spanK, ipRangeMK, specKS, urlmK}
			inf := func(i int) {
				fm := func(m map[string]interface{}) {
					c.res.add(rs[i], m)
				}
				c.sliceMap(rs[i], fm, fe, func() bool { return e == nil })
			}
			forall(inf, len(rs))
		},
	}
	trueFF(fs, func() bool { return e == nil })
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

func (c *conf) sliceMap(key string, fm func(map[string]interface{}),
	fe func(error), bf func() bool) {
	vs, e := c.sliceE(key)
	nfe := func(d error) {
		if d != nil {
			e := fmt.Errorf("Reading '%s': %s", key, d.Error())
			fe(e)
		}
	}
	if e == nil {
		inf := func(i int) (b bool) {
			vi := stringMapE(vs[i], nfe)
			b = bf()
			if b {
				fm(vi)
				b = bf()
			}
			return
		}
		trueForall(inf, len(vs))
	} else {
		nfe(e)
	}
	return
}

func (c *conf) configPath() (dir string) {
	dir = path.Dir(viper.ConfigFileUsed())
	return
}
