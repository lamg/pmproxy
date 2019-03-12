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
	"github.com/spf13/cast"
	"time"
)

type intBool func(int) bool

// bLnSrch is the bounded lineal search algorithm
// { n ≥ 0 ∧ forall.n.(def.ib) }
// { i =⟨↑j: 0 ≤ j ≤ n ∧ ⟨∀k: 0 ≤ k < j: ¬ib.k⟩: j⟩
//   ∧ b ≡ i ≠ n }
func bLnSrch(ib intBool, n int) (b bool, i int) {
	b, i, udb := false, 0, true
	// udb: undefined b for i
	for !b && i != n {
		if udb {
			// udb ∧ i ≠ n
			b, udb = ib(i), false
		} else {
			// ¬udb ∧ ¬b
			i, udb = i+1, true
		}
	}
	return
}

func trueForall(ib intBool, n int) (ok bool, i int) {
	r, i := bLnSrch(
		func(i int) (b bool) {
			b = !ib(i)
			return
		},
		n,
	)
	// calculated showing that doesn't exists function
	// yielding false
	ok = !r
	return
}

type intF func(int)

func forall(inf intF, n int) {
	for i := 0; i != n; i++ {
		inf(i)
	}
}

func ferror(fe []func(), errb func() bool) (ib intBool) {
	ib = func(i int) (ok bool) {
		fe[i]()
		ok = errb()
		return
	}
	return
}

type kFuncI struct {
	k string
	f fin
}

func mpErr(m map[string]interface{}, fi fin,
	fe ferr) (fk func(string)) {
	fk = func(k string) {
		v, ok := m[k]
		if ok {
			fi(v)
		} else {
			fe(noKey(k))
		}
	}
	return
}

func mapKF(kf []kFuncI, i interface{}, fe ferr,
	fb func() bool) {
	m, e := cast.ToStringMapE(i)
	if e == nil {
		me := func(fi fin) (fk func(string)) {
			fk = mpErr(m, fi, fe)
			return
		}
		trueForall(
			func(i int) (b bool) {
				me(kf[i].f)(kf[i].k)
				b = fb()
				return
			},
			len(kf),
		)
	} else {
		fe(e)
	}
}

type kFunc struct {
	k string
	f func()
}

func optionalKeys(fe ferr, keys ...string) (fek ferr) {
	fek = func(e error) {
		ib := func(i int) (b bool) {
			b = e != nil && e.Error() == noKey(keys[i]).Error()
			return
		}
		optK, _ := bLnSrch(ib, len(keys))
		if optK {
			e = nil
		}
		fe(e)
	}
	return
}

func exF(kf []kFunc, key string, fe ferr) {
	ib := func(i int) (b bool) {
		b = kf[i].k == key
		return
	}
	ok, n := bLnSrch(ib, len(kf))
	if ok {
		kf[n].f()
	} else {
		fe(noKey(key))
	}
	return
}

type cmdProp struct {
	cmd  string
	prop string
	f    func()
}

func stringE(i interface{}, fe ferr) (s string) {
	s, e := cast.ToStringE(i)
	fe(e)
	return
}

func stringSliceE(i interface{}, fe ferr) (ss []string) {
	ss, e := cast.ToStringSliceE(i)
	fe(e)
	return
}

func durationE(i interface{},
	fe ferr) (d time.Duration) {
	s, e := cast.ToStringE(i)
	if e == nil {
		d, e = time.ParseDuration(s)
	}
	fe(e)
	return
}

func stringMapE(i interface{},
	fe ferr) (m map[string]interface{}) {
	m, e := cast.ToStringMapE(i)
	fe(e)
	return
}

func stringMapUint64E(i interface{},
	fe ferr) (m map[string]uint64) {
	m, ok := i.(map[string]uint64)
	if !ok {
		fe(fmt.Errorf("Failed cast to map[string]uint64"))
	}
	return
}

func stringMapStringE(i interface{},
	fe ferr) (m map[string]string) {
	m, e := cast.ToStringMapStringE(i)
	fe(e)
	return
}

func stringMapStringSlice(i interface{},
	fe ferr) (m map[string][]string) {
	m, e := cast.ToStringMapStringSliceE(i)
	fe(e)
	return
}

type ferr func(error)
type fbs func([]byte)
type fin func(interface{})
type fikf func(int) []kFuncI

func int64E(i interface{}, fe ferr) (n int64) {
	n, e := cast.ToInt64E(i)
	fe(e)
	return
}

func uint32E(i interface{}, fe ferr) (n uint32) {
	n, e := cast.ToUint32E(i)
	fe(e)
	return
}

func intE(i interface{}, fe ferr) (n int) {
	n, e := cast.ToIntE(i)
	fe(e)
	return
}

func stringDateE(i interface{}, fe ferr) (t time.Time) {
	s, e := cast.ToStringE(i)
	if e == nil {
		t, e = time.Parse(time.RFC3339, s)
	}
	fe(e)
	return
}

func boolE(i interface{}, fe ferr) (b bool) {
	b, e := cast.ToBoolE(i)
	fe(e)
	return
}

type choice struct {
	guard func() bool
	runf  func() error
}

func runChoice(chs []choice) (ok bool, i int, e error) {
	ib := func(i int) (b bool) {
		b = chs[i].guard()
		return
	}
	ok, i = bLnSrch(ib, len(chs))
	if ok {
		e = chs[i].runf()
	}
	return
}

func runConcurr(fe []func() error) (e error) {
	ec := make(chan error)
	runf := func(i int) {
		go func() {
			ec <- fe[i]()
		}()
	}
	forall(runf, len(fe))
	e = <-ec
	return
}

// trueFF means true forall function
func trueFF(fs []func(), okf func() bool) (ok bool) {
	ok, _ = trueForall(func(i int) (b bool) {
		fs[i]()
		b = okf()
		return
	},
		len(fs),
	)
	return
}
