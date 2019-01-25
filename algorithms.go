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
	f fin
}

func mpErr(m map[string]interface{}, fi fin,
	fe ferr) (fk func(string)) {
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

func mapKF(kf []kFuncI, i interface{}, fe ferr,
	fb func() bool) {
	m, e := cast.ToStringMapE(i)
	if e == nil {
		me := func(fi fin) (fk func(string)) {
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

func exF(kf []kFunc, cmd string, fe ferr) {
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

type cmdProp struct {
	cmd  string
	prop string
	f    func()
}

func exCmdProp(cs []cmdProp, fe ferr) {
	cmdf, propf := false, false
	bLnSrch(
		func(i int) (b bool) {
			cmdf, propf = cs[i].cmd == a.Cmd, cs[i].prop == a.Prop
			b = cmdf && propf
			if b {
				cs[i].f()
			}
		},
		len(cs),
	)
	if !cmdf {
		fe(NoCmd(a.Cmd))
	} else if !propf {
		fe(NoProp(a.Prop))
	}
}

func stringE(fc func(interface{}) (string, error),
	fe ferr) (f func(interface{}) string) {
	f = func(i interface{}) (s string) {
		s, e := fc(i)
		fe(e)
		return
	}
	return
}

func stringSliceE(fc func(interface{}) ([]string, error),
	fe ferr) (f func(interface{}) string) {
	f = func(i interface{}) (ss []string) {
		ss, e := fc(i)
		fe(e)
		return
	}
	return
}

func stringDurationE(
	fc func(interface{}) (time.Duration, error), fe ferr,
) (f func(interface{}) time.Duration) {
	f = func(i interface{}) (d time.Duration) {
		d, e := fc(i)
		fe(e)
		return
	}
	return
}

func stringMapE(
	fc func(interface{}) (map[string]interface{}, error),
	fe ferr,
) (f func(i interface{}) map[string]interface{}) {
	f = func(i interface{}) (m map[string]interface{}) {
		m, e := fc(i)
		fe(e)
	}
	return
}

func stringMapUint64E(
	fc func(interface{}) (map[string]uint64, error),
	fe ferr,
) (f func(i interface{}) map[string]uint64) {
	f = func(i interface{}) (m map[string]uint64) {
		m, e := fc(i)
		fe(e)
		return
	}
	return
}

type ferr func(error)
type fbs func([]byte)
type fin func(interface{})

func int64E(fc func(interface{}) (int64, error),
	fe ferr) (f fin) {
	f = func(i interface{}) (n int64) {
		n, e := fc(i)
		fe(e)
		return
	}
	return
}

func uint32E(fc func(interface{}) (uint32, error),
	fe ferr) (f fin) {
	f = func(i interface{}) (n uint32) {
		n, e := fc(i)
		fe(e)
		return
	}
	return
}

func stringToDuration(i interface{}) (d time.Duration,
	e error) {
	s, e := cast.ToStringE(i)
	if e == nil {
		d, e = time.ParseDuration(s)
	}
	return
}
