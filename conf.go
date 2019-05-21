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
	"fmt"
	"github.com/BurntSushi/toml"
	pred "github.com/lamg/predicate"
	"github.com/spf13/afero"
	"github.com/spf13/cast"
	"os"
	"path"
	"time"
)

type Conf struct {
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

func controlConn(op *proxy.Operation) (r *proxy.Restult) {
	return
}

func NewConf(fls afero.Fs, now func() time.Time) (c *Conf,
	e error) {
	c = &Conf{fls: fls, now: now}
	var fl afero.File
	fs := []func(){
		func() {
			c.filePath = ConfPath()
			c.staticFPath = c.strïng(staticFilesPathK,
				path.Join(home(), homeConfigDir, staticFilesDir))
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
				c.strïng(waitUpdateK, "1m"))
		},
		func() { e = c.initLogger() },
		func() { e = c.readProxyConf() },
		func() { e = c.readIfaceConf() },
		func() { e = c.initResources() },
		func() { e = c.initConnMng() },
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func ConfPath() (p string) {
	p = path.Join(home(), homeConfigDir, configFile)
	return
}

func (c *Conf) Update() (e error) {
	cf := make(map[string]interface{})
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
		ok = true
		return
	})
	cf[proxyConfK] = c.proxy.toMap()
	cf[ifaceConfK] = c.iface.toMap()
	cf[connMngK] = c.cm.toMap()
	cf[rulesK] = pred.String(c.res.rules)
	cf[adminsK] = c.res.admins
	cf[loggerAddrK] = c.lg.addr
	cf[waitUpdateK] = c.waitUpd.String()
	fl, e := c.fls.Create(c.filePath)
	if e == nil {
		enc := toml.NewEncoder(fl)
		e = enc.Encode(&cf)
		fl.Close()
	}
	// all serializable components are encoded
	return
}

func (c *Conf) initConnMng() (e error) {
	// c.initRules()
	c.cm = new(connMng)
	v, ok := c.base[connMngK]
	if !ok {
		v = map[string]interface{}{
			maxIdleK: 0,
			idleTK:   "0s",
			tlsHTK:   "0s",
			expCTK:   "0s",
			timeoutK: "60s",
		}
	}
	e = c.cm.fromMap(v)
	c.cm.consR = func(name string) (cr *consR, ok bool) {
		v, ok := c.res.managers.Load(name)
		if ok {
			cr = v.(*manager).consR
			ok = cr != nil
		}
		return
	}
	c.cm.log = c.lg.log
	c.cm.match = c.res.match
	c.cm.user = c.res.iu.get
	mng := &manager{
		tÿpe: connMngK,
	}
	c.res.managers.Store(connMngK, mng)
	return
}

func genConfig(fls afero.Fs) (e error) {
	var dir string
	fs := []func(){
		func() {
			dirs := []string{
				path.Join(home(), homeConfigDir),
			}
			ib := func(i int) (b bool) {
				e = fls.MkdirAll(dirs[i], os.ModeDir|os.ModePerm)
				stDir := path.Join(dirs[i], staticFilesDir)
				fls.MkdirAll(stDir, os.ModeDir|os.ModePerm)
				afero.WriteFile(fls, path.Join(stDir, "index.html"),
					[]byte(indexHTML), 0644)
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
			e = BasicConf(fl, fls)
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

func (c *Conf) readProxyConf() (e error) {
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
		if s == NoKey(certK).Error() || s == NoKey(keyK).Error() {
			e = nil
		}
	}
	if c.proxy != nil {
		c.proxy.proxyOrIface = true
	}
	return
}

func (c *Conf) readIfaceConf() (e error) {
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
	if e == nil {
		c.iface.proxyOrIface = false
	}
	return
}

func (c *Conf) initLogger() (e error) {
	c.lg, e = newLogger(c.strïng(loggerAddrK, ""))
	return
}

func (c *Conf) initResources() (e error) {
	fe := func(d error) { e = d }
	var predCf string
	var expiration time.Duration
	fs := []func(){
		func() {
			predCf = c.strïng(rulesK, pred.TrueStr)
		},
		func() {
			expiration = c.duration(expirationK, defaultExpiration)
		},
		func() {
			c.res, e = newResources(predCf, c.stringSlice(adminsK),
				c.fls, c.lg.warning, c.now, expiration)
		},
		func() {
			c.res.debug = cast.ToBool(c.base[debugK])
			rs := []string{UserDBK, SessionIPMK, DwnConsRK, BwConsRK,
				groupIPMK, spanK, rangeIPMK, urlmK}
			inf := func(i int) {
				fm := func(m map[string]interface{}) {
					d := c.res.add(rs[i], m)
					if d != nil {
						ne := fmt.Sprintf("Reading %s: %s", rs[i], d.Error())
						c.lg.warning(ne)
					}
				}
				c.sliceMap(rs[i], fm, fe, func() bool { return e == nil })
			}
			forall(inf, len(rs))
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

func (c *Conf) sliceE(key string) (sl []interface{},
	e error) {
	v, ok := c.base[key]
	if ok {
		sl, e = cast.ToSliceE(v)
	} else {
		e = NoKey(key)
	}
	return
}

func (c *Conf) stringSlice(key string) (sl []string) {
	sv, _ := c.sliceE(key)
	inf := func(i int) {
		sl = append(sl, cast.ToString(sv[i]))
	}
	forall(inf, len(sv))
	return
}

func (c *Conf) strïng(key, def string) (s string) {
	i, ok := c.base[key]
	if !ok {
		s = def
	} else {
		s = cast.ToString(i)
	}
	return
}

func (c *Conf) duration(key, def string) (d time.Duration) {
	s := c.strïng(key, def)
	d, _ = time.ParseDuration(s)
	return
}

func (c *Conf) sliceMap(key string, fm func(map[string]interface{}),
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

func BasicConf(pth string, fs afero.Fs) (e error) {
	e = afero.WriteFile(fs, pth, []byte(basicConfText), 0644)
	return
}
