package pmproxy

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
