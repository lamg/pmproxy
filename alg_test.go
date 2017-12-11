package pmproxy

import (
	"fmt"
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

func TestMultMsg(t *testing.T) {
	l := 10
	mcs, mc := make([]chan string, l), make(chan string, l)
	for i := 0; i != l; i++ {
		mcs[i] = make(chan string, 1)
		mcs[i] <- fmt.Sprintf("%d", i)
	}
	go MultMsg(mcs, mc)
	for i := 0; i != l; i++ {
		msg := <-mc
		require.Equal(t, msg, fmt.Sprintf("%d", i))
	}
	require.Equal(t, "", <-mc)
}
