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
	"encoding/json"
	pred "github.com/lamg/predicate"
	rt "github.com/lamg/rtimespan"
	"io/ioutil"
	//"net"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

type resources struct {
	rules      *pred.Predicate
	specs      *sync.Map
	matchers   *sync.Map
	managerKFs *sync.Map
	consRs     *sync.Map
	mappers    *sync.Map
	userDBs    *sync.Map
	iu         *ipUserS
	cr         *crypt
	admins     []string
}

func (r *resources) match(ürl, rAddr string,
	t time.Time) (s *spec) {
	s = new(spec)
	interp := func(name string) (v, ok bool) {
		vsp, ok := r.specs.Load(name)
		if ok {
			join(s, vsp.(*spec))
			v = true
		} else {
			var mt interface{}
			mt, ok = r.matchers.Load(name)
			if ok {
				matcher := mt.(func(string, string, time.Time) bool)
				v = matcher(ürl, rAddr, t)
			}
		}
		return
	}
	s.Result = pred.Reduce(r.rules, interp)
	return
}

func (r *resources) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			add,
			func() {
				c.e = r.add(c.String, c.Object)
			},
		},
		{
			set,
			func() {
				rd := strings.NewReader(c.String)
				r.rules, c.e = pred.Parse(rd)
			},
		},
		{
			show,
			func() {
				c.bs = []byte(pred.String(r.rules))
			},
		},
		{
			discover,
			func() {
				r.match("", c.RemoteAddr, time.Now())
			},
		},
	}
	// TODO show, delete spec
	return
}

func (r *resources) add(tÿpe string,
	par map[string]interface{}) (e error) {
	fs := map[string]func(map[string]interface{}) error{
		urlmK:       r.addURLM,
		spanK:       r.addSpan,
		ipRangeMK:   r.addRangeIPM,
		groupIPMK:   r.addGroupIPM,
		sessionIPMK: r.addSessionIPM,
		specKS:      r.addSpec,
		userDBK:     r.addUserDB,
		dwnConsRK:   r.addDwnConsR,
	}
	fm, ok := fs[tÿpe]
	if ok {
		e = fm(par)
	} else {
		e = noKey(tÿpe)
	}
	return
}

func (r *resources) addURLM(m map[string]interface{}) (e error) {
	fe := func(d error) { e = d }
	var name, urlReg string
	var parReg *regexp.Regexp
	kf := []kFuncI{
		{nameK, func(i interface{}) { name = stringE(i, fe) }},
		{regexpK, func(i interface{}) { urlReg = stringE(i, fe) }},
		{
			regexpK,
			func(i interface{}) { parReg, e = regexp.Compile(urlReg) },
		},
		{
			regexpK,
			func(i interface{}) {
				r.matchers.Store(name,
					func(ürl, ip string, t time.Time) bool {
						return parReg.MatchString(ürl)
					})
				r.mappers.Store(name,
					func() (m map[string]interface{}) {
						m = map[string]interface{}{
							nameK:   name,
							regexpK: urlReg,
						}
						return
					})
			},
		},
	}
	mapKF(kf, m, fe, func() bool { return e == nil })
	return
}

func (r *resources) addSpan(m map[string]interface{}) (e error) {
	sp := new(rt.RSpan)
	name, e := fromMapSpan(sp, m)
	if e == nil {
		r.matchers.Store(name,
			func(ürl, ip string, t time.Time) (ok bool) {
				ok = sp.ContainsTime(t)
				return
			})
		r.mappers.Store(name, func() (m map[string]interface{}) {
			m = toMapSpan(sp, name)
			return
		})
	}
	return
}

func (r *resources) addRangeIPM(
	m map[string]interface{}) (e error) {
	rg := new(rangeIPM)
	e = rg.fromMap(m)
	if e == nil {
		fm := wrapIPMatcher(rg.match)
		r.matchers.Store(rg.name, fm)
		r.managerKFs.Store(rg.name, rg.managerKF)
		r.mappers.Store(rg.name, rg.toMap)
	}
	return
}

func (r *resources) addSessionIPM(
	m map[string]interface{},
) (e error) {
	sm := &sessionIPM{
		iu: r.iu,
		cr: r.cr,
	}
	e = sm.fromMap(m)
	if e == nil {
		sm.nameAuth = r.authenticator
		r.managerKFs.Store(sm.name, sm.managerKF)
		r.matchers.Store(sm.name, wrapIPMatcher(sm.match))
		r.mappers.Store(sm.name, sm.toMap)
	}
	return
}

func (r *resources) addDwnConsR(
	m map[string]interface{}) (e error) {
	homeData := path.Join(home(), dataDir)
	dw := &dwnConsR{
		fileReader: func(file string) (bs []byte, d error) {
			bs, d = ioutil.ReadFile(path.Join(homeData, file))
			return
		},
	}
	e = dw.fromMap(m)
	if e == nil {
		v, ok := r.userDBs.Load(dw.userQuotaN)
		if ok {
			dw.userQuota = v.(*userDB).quota
		} else {
			e = noKey(dw.userQuotaN)
		}
	}
	if e == nil {
		dw.mapWriter = func(mp map[string]uint64) {
			var bs []byte
			var d error
			fs := []func(){
				func() { bs, d = json.Marshal(mp) },
				func() {
					ioutil.WriteFile(
						path.Join(homeData, dw.name+".json"),
						bs,
						0644,
					)
				},
			}
			trueFF(fs,
				func() bool { return d == nil })
		}
		r.managerKFs.Store(dw.name, dw.managerKF)
		r.consRs.Store(dw.name, dw.consR())
		r.mappers.Store(dw.name, dw.toMap)
	}
	return
}

func (r *resources) authenticator(name string) (
	a func(string, string) (string, error),
	ok bool,
) {
	v, ok := r.userDBs.Load(name)
	if ok {
		a = v.(*userDB).auth
	}
	return
}

func (r *resources) addGroupIPM(
	m map[string]interface{}) (e error) {
	gipm := new(groupIPM)
	e = gipm.fromMap(m)
	if e == nil {
		v, ok := r.userDBs.Load(gipm.userGroupN)
		if ok {
			gipm.userGroup = v.(*userDB).userGroups
			r.managerKFs.Store(gipm.name, gipm.managerKF)
			r.mappers.Store(gipm.name, gipm.toMap)
			r.matchers.Store(gipm.name, gipm.match)
		} else {
			e = noKey(gipm.userGroupN)
		}
	}
	return
}

func (r *resources) addSpec(m map[string]interface{}) (e error) {
	sp := new(spec)
	e = sp.fromMap(m)
	if e == nil {
		r.specs.Store(sp.Name, sp)
	}
	return
}

func (r *resources) addUserDB(m map[string]interface{}) (e error) {
	udb := new(userDB)
	e = udb.fromMap(m)
	if e == nil {
		r.managerKFs.Store(udb.name, udb.managerKF)
		r.mappers.Store(udb.name, udb.toMap)
		r.userDBs.Store(udb.name, udb)
	}
	return
}

func wrapIPMatcher(m func(string) bool) (
	w func(string, string, time.Time) bool) {
	w = func(ürl, ip string, t time.Time) (ok bool) {
		ok = m(ip)
		return
	}
	return
}

func (r *resources) manager(m *cmd) {
	m.User, _ = r.iu.get(m.RemoteAddr)
	m.IsAdmin, _ = bLnSrch(
		func(i int) bool {
			return r.admins[i] == m.User
		},
		len(r.admins),
	)
	v, ok := r.managerKFs.Load(m.Manager)
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
					r.managerKFs.Range(
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
