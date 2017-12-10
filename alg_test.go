package pmproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLS(t *testing.T) {
	a := make([]int, 10)
	for i := range a {
		a[i] = i
	}
	for i, j := range a {
		b := make(chan bool)
		go EqX(a, j, b)
		n := LS(b)
		require.Equal(t, i, n)
	}
}
