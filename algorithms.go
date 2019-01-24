package pmproxy

import (
	"github.com/spf13/cast"
)

type intBool func(int) bool

// bLnSrch is the bounded lineal search algorithm
// { n ≥ 0 ∧ ⟨∀i: 0 ≤ i < n: def.(ib.i)⟩ }
// { i = ⟨↑j: 0 ≤ j ≤ n ∧ ⟨∀k: 0 ≤ k < j: ¬ib.k⟩: j⟩ ∧
//   b ≡ i ≠ n }
func bLnSrch(ib intBool, n int) (b bool, i int) {
	b, i = false, 0
	for !b && i != n {
		b = ib(i)
		if !b {
			i = i + 1
		}
	}
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
	f func(interface{})
}

func mpErr(m map[string]interface{}, fi func(interface{}),
	fe func(error)) (fk func(string)) {
	fk = func(k string) {
		v, ok := m[k]
		if ok {
			fi(v)
		} else {
			fe(NoKey(k))
		}
	}
	return
}

func mapKF(kf []kFuncI, i interface{}, fe func(error),
	fb func() bool) {
	m, e := cast.ToStringMapE(i)
	if e == nil {
		me := func(fi func(interface{})) (fk func(string)) {
			fk = mpErr(m, fi, fe)
			return
		}
		bLnSrch(
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

func exF(kf []kFunc, cmd string, fe func(error)) {
	ok, _ := bLnSrch(
		func(i int) (b bool) {
			b = cmd == kf[i].k
			if b {
				kf[i].f()
			}
		},
		len(kf),
	)
	if !ok {
		fe(NoCmd(cmd))
	}
	return
}
