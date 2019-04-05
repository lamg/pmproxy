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
	"fmt"
	pred "github.com/lamg/predicate"
	rt "github.com/lamg/rtimespan"
	"github.com/spf13/afero"
	"os"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"
)

type resources struct {
	rules    *pred.Predicate
	managers *sync.Map
	iu       *ipUserS
	cr       *crypt
	admins   []string
	fls      afero.Fs
}

func (r *resources) match(ürl, rAddr string,
	t time.Time) (s *spec) {
	s = new(spec)
	interp := func(name string) (v, ok bool) {
		m, ok := r.managers.Load(name)
		if ok {
			mng := m.(*manager)
			if mng.spec != nil {
				join(s, mng.spec, name)
				v = true
			} else {
				ok = mng.matcher != nil
				if ok {
					v = mng.matcher(ürl, rAddr, t)
				}
			}
		}
		return
	}
	s.Result = pred.Reduce(r.rules, interp)
	return
}

type discoverRes struct {
	Matching   []string        `json:"matching"`
	NoMatching []string        `json:"noMatching"`
	Result     *pred.Predicate `json:"result"`
}

func (r *resources) filterMatch(ürl, rAddr string,
	t time.Time) (dr *discoverRes) {
	dr = new(discoverRes)
	interp := func(name string) (v, ok bool) {
		m, ok := r.managers.Load(name)
		if ok {
			mng := m.(*manager)
			v = mng.spec != nil
			if !v && mng.matcher != nil {
				v = mng.matcher(ürl, rAddr, t)
			}
		}
		if ok {
			if v {
				dr.Matching = append(dr.Matching, name)
			} else {
				dr.NoMatching = append(dr.NoMatching, name)
			}
		}
		return
	}
	dr.Result = pred.Reduce(r.rules, interp)
	return
}

type manager struct {
	tÿpe      string
	managerKF func(*cmd) []kFunc
	mapper    func() map[string]interface{}
	matcher   func(string, string, time.Time) bool
	consR     *consR
	udb       *userDB
	spec      *spec
}

func newResources(predicate string, admins []string,
	fls afero.Fs) (r *resources, e error) {
	r = &resources{
		managers: new(sync.Map),
		iu:       newIPuserS(),
		admins:   admins,
		fls:      fls,
	}
	r.managers.Store(resourcesK, &manager{
		tÿpe:      resourcesK,
		managerKF: r.managerKF,
	})
	r.rules, e = pred.Parse(strings.NewReader(predicate))
	if e == nil {
		r.cr, e = newCrypt()
	} else {
		e = fmt.Errorf("Parsing predicate '%s': %s", predicate,
			e.Error())
	}
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
			get,
			func() {
				v, ok := r.managers.Load(c.String)
				if ok {
					c.bs = []byte(v.(*manager).tÿpe)
				} else {
					c.e = noKey(c.String)
				}
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
			filter,
			func() {
				ms := r.availableMng(r.rules, c.String)
				c.bs, c.e = json.Marshal(ms)
			},
		},
		{
			discover,
			func() {
				dr := r.filterMatch(c.String, c.RemoteAddr, time.Now())
				c.bs, c.e = json.Marshal(dr)
			},
		},
		{
			specKS,
			func() {
				v, ok := r.managers.Load(c.String)
				var mng *manager
				if ok {
					mng = v.(*manager)
					if mng.spec != nil {
						c.bs, c.e = json.Marshal(mng.spec)
					} else {
						c.e = noKey(c.String + " with spec field")
					}
				} else {
					c.e = noKey(c.String)
				}
			},
		},
	}
	// TODO show, delete spec
	return
}

func (r *resources) availableMng(p *pred.Predicate, tÿpe string) (ms []string) {
	if p != nil {
		if p.Operator == pred.Term {
			v, ok := r.managers.Load(p.String)
			if ok && v.(*manager).tÿpe == tÿpe {
				ms = []string{p.String}
			}
		} else {
			ms = append(r.availableMng(p.A, tÿpe),
				r.availableMng(p.B, tÿpe)...)
		}
	}
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
		userDBK:     r.addUserDB,
		dwnConsRK:   r.addDwnConsR,
		specKS:      r.addSpec,
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
				mng := &manager{
					tÿpe: urlmK,
					matcher: func(ürl, ip string, t time.Time) bool {
						return parReg.MatchString(ürl)
					},
					mapper: func() (m map[string]interface{}) {
						m = map[string]interface{}{
							nameK:   name,
							regexpK: urlReg,
						}
						return
					},
				}
				r.managers.Store(name, mng)
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
		mng := &manager{
			tÿpe: spanK,
			matcher: func(ürl, ip string, t time.Time) (ok bool) {
				ok = sp.ContainsTime(t)
				return
			},
			mapper: func() (m map[string]interface{}) {
				m = toMapSpan(sp, name)
				return
			},
		}
		r.managers.Store(name, mng)
	}
	return
}

func (r *resources) addRangeIPM(
	m map[string]interface{}) (e error) {
	rg := new(rangeIPM)
	e = rg.fromMap(m)
	if e == nil {
		fm := wrapIPMatcher(rg.match)
		mng := &manager{
			tÿpe:      rangeIPMT,
			matcher:   fm,
			managerKF: rg.managerKF,
			mapper:    rg.toMap,
		}
		r.managers.Store(rg.name, mng)
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
		mng := &manager{
			tÿpe:      sessionIPMK,
			managerKF: sm.managerKF,
			matcher:   wrapIPMatcher(sm.match),
			mapper:    sm.toMap,
		}
		r.managers.Store(sm.name, mng)
	}
	return
}

func (r *resources) addDwnConsR(
	m map[string]interface{}) (e error) {
	homeData := path.Join(home(), dataDir)
	dw := &dwnConsR{
		fileReader: func(file string) (bs []byte, d error) {
			bs, d = afero.ReadFile(r.fls, path.Join(homeData, file))
			return
		},
	}
	e = dw.fromMap(m)
	if e == nil {
		v, ok := r.managers.Load(dw.userQuotaN)
		var mng *manager
		if ok {
			mng = v.(*manager)
			ok = mng.udb != nil
		}
		if ok {
			dw.userQuota = mng.udb.quota
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
					r.fls.MkdirAll(homeData, os.ModeDir|os.ModePerm)
					afero.WriteFile(r.fls, path.Join(homeData, dw.name+".json"),
						bs, 0644)
				},
			}
			trueFF(fs,
				func() bool { return d == nil })
		}
		mng := &manager{
			tÿpe:      dwnConsRK,
			managerKF: dw.managerKF,
			consR:     dw.consR(),
			mapper:    dw.toMap,
		}
		r.managers.Store(dw.name, mng)
	}
	return
}

func (r *resources) authenticator(name string) (
	a func(string, string) (string, error),
	ok bool,
) {
	v, ok := r.managers.Load(name)
	var mng *manager
	if ok {
		mng = v.(*manager)
		ok = mng.udb != nil
	}
	if ok {
		a = mng.udb.auth
	}
	return
}

func (r *resources) addGroupIPM(
	m map[string]interface{}) (e error) {
	gipm := new(groupIPM)
	e = gipm.fromMap(m)
	if e == nil {
		v, ok := r.managers.Load(gipm.userGroupN)
		var mng *manager
		if ok {
			mng = v.(*manager)
			ok = mng.udb != nil
		}
		if ok {
			gipm.userGroup = mng.udb.userGroups
			mng := &manager{
				tÿpe:      groupIPMK,
				managerKF: gipm.managerKF,
				mapper:    gipm.toMap,
				matcher:   wrapIPMatcher(gipm.match),
			}
			r.managers.Store(gipm.name, mng)
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
		v, ok := r.managers.Load(sp.Name)
		if ok {
			mng := v.(*manager)
			mng.spec = sp
		}
	}
	return
}

func (r *resources) addUserDB(m map[string]interface{}) (e error) {
	udb := new(userDB)
	e = udb.fromMap(m)
	if e == nil {
		mng := &manager{
			tÿpe:      userDBK,
			managerKF: udb.managerKF,
			mapper:    udb.toMap,
			udb:       udb,
		}
		r.managers.Store(udb.name, mng)
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
	v, ok := r.managers.Load(m.Manager)
	var kf []kFunc
	if ok {
		kf = v.(*manager).managerKF(m) // calculated risk
		kf = append(kf,
			kFunc{skip, func() {}},
			kFunc{
				showAll,
				func() {
					mngs := make([]string, 0)
					r.managers.Range(
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
