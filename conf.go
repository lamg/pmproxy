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
	"github.com/BurntSushi/toml"
	pred "github.com/lamg/predicate"
	"github.com/spf13/afero"
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
	fls         afero.Fs
	staticFPath string

	lg      *logger
	res     *resources
	cm      *connMng
	proxy   *srvConf
	iface   *srvConf
	waitUpd time.Duration

	base     map[string]interface{}
	filePath string
}

func newConf(fls afero.Fs) (c *conf, e error) {
	c = &conf{fls: fls}
	var fl afero.File
	fs := []func(){
		func() {
			c.filePath = confPath()
			fl, e = fls.Open(c.filePath)
			if e != nil {
				e = genConfig(fls)
			}
		},
		func() {
			fl, e = fls.Open(c.filePath)
		},
		func() {
			_, e = toml.DecodeReader(fl, &c.base)
			fl.Close()
		},
		func() {
			c.waitUpd, e = time.ParseDuration(
				c.strïng(waitUpdateK, "5m"))
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

func confPath() (p string) {
	p = path.Join(home(), homeConfigDir, configFile)
	return
}

func (c *conf) update() (e error) {
	var cf map[string]interface{}
	c.res.managers.Range(func(k, v interface{}) (ok bool) {
		mng := v.(*manager)
		if mng.mapper != nil {
			mp := mng.mapper()
			v, ok := cf[mng.tÿpe]
			if ok {
				sv := v.([]interface{})
				sv = append(sv, mp)
				cf[mng.tÿpe] = sv
			} else {
				cf[mng.tÿpe] = []interface{}{mp}
			}
		}
		return
	})
	cf[proxyConfK] = c.proxy.toMap()
	cf[ifaceConfK] = c.iface.toMap()
	cf[rulesK] = pred.String(c.res.rules)
	cf[adminsK] = c.res.admins
	cf[loggerAddrK] = c.lg.addr
	cf[waitUpdateK] = c.waitUpd.String()
	fl, e := c.fls.Open(c.filePath)
	if e == nil {
		enc := toml.NewEncoder(fl)
		e = enc.Encode(&cf)
	}
	// all serializable components are in encoded
	return
}

func (c *conf) initConnMng() (e error) {
	// c.initRules()
	c.cm = new(connMng)
	v, ok := c.base[connMngK]
	if !ok {
		v = map[string]interface{}{
			maxIdleK: 0,
			idleTK:   "0s",
			tlsHTK:   "0s",
			expCTK:   "0s",
		}
	}
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
		timeout: c.duration(timeoutK, "15s"),
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

func genConfig(fls afero.Fs) (e error) {
	var dir string
	fs := []func(){
		func() {
			dirs := []string{
				mainConfigDir,
				path.Join(home(), homeConfigDir),
			}
			ib := func(i int) (b bool) {
				e = fls.MkdirAll(dirs[i], os.ModeDir|os.ModePerm)
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
			e = basicConf(fl, fls)
		},
		func() {
			key := path.Join(dir, defaultSrvKey)
			cert := path.Join(dir, defaultSrvCert)
			e = genCert(defaultHost, key, cert, fls)
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func (c *conf) readProxyConf() (e error) {
	i, ok := c.base[proxyConfK]
	if !ok {
		i = map[string]interface{}{
			fastOrStdK:    false,
			readTimeoutK:  30 * time.Second,
			writeTimeoutK: 40 * time.Second,
			addrK:         ":8080",
		}
	}
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
	i, ok := c.base[ifaceConfK]
	if !ok {
		i = map[string]interface{}{
			fastOrStdK:    false,
			readTimeoutK:  10 * time.Second,
			writeTimeoutK: 15 * time.Second,
			addrK:         ":4443",
			certK:         defaultSrvCert,
			keyK:          defaultSrvKey,
		}
	}
	c.iface, e = readSrvConf(i)
	return
}

func (c *conf) initLogger() (e error) {
	c.lg, e = newLogger(c.strïng(loggerAddrK, ""))
	return
}

func (c *conf) initResources() (e error) {
	fe := func(d error) { e = d }
	var predCf string
	fs := []func(){
		func() {
			predCf = c.strïng(rulesK, pred.TrueStr)
		},
		func() {
			c.res, e = newResources(predCf, c.stringSlice(adminsK))
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

func (c *conf) sliceE(key string) (sl []interface{},
	e error) {
	v, ok := c.base[key]
	if ok {
		sl, e = cast.ToSliceE(v)
	} else {
		e = noKey(key)
	}
	return
}

func (c *conf) stringSlice(key string) (sl []string) {
	sv, _ := c.sliceE(key)
	inf := func(i int) {
		sl = append(sl, cast.ToString(sv[i]))
	}
	forall(inf, len(sv))
	return
}

func (c *conf) strïng(key, def string) (s string) {
	i, ok := c.base[key]
	if !ok {
		s = def
	} else {
		s = cast.ToString(i)
	}
	return
}

func (c *conf) duration(key, def string) (d time.Duration) {
	s := c.strïng(key, def)
	d, _ = time.ParseDuration(s)
	return
}

func (c *conf) sliceMap(key string, fm func(map[string]interface{}),
	fe func(error), bf func() bool) {
	vs, e := c.sliceE(key)
	nfe := func(d error) {
		if d != nil {
			nd := fmt.Errorf("Reading '%s': %s", key, d.Error())
			fe(nd)
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
	}
	return
}

func basicConf(pth string, fs afero.Fs) (e error) {
	e = afero.WriteFile(fs, pth, []byte(basicConfText), 0644)
	return
}
