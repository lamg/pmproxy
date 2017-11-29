package pmproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

type eq struct {
	n int
}

func (e *eq) Eval(v interface{}) (y bool) {
	x, y := v.(int)
	y = y && x == e.n
	return
}

func TestForAllExists(t *testing.T) {
	s, rn := [][]int{
		{3, 4, 5},
		{6, 7, 3},
		{18, 4, 3},
	},
		[]int{0, 2, 2} //index of 3 in each array

	r := make([][]Predicate, len(s))
	for i, j := range s {
		r[i] = &eq{j}
	}
	y, n := ForAllExists(r, 3)
	require.True(t, y)
	for i := 0; i != len(rn); i++ {
		require.True(t, rn[i] == n[i])
	}
}
