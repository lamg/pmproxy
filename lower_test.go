package pmproxy

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestMyLower(t *testing.T) {
	ts := []struct {
		org string
		r   string
	}{
		{"Ángel", "angel"},
		{"žůžo", "zuzo"},
	}
	for i, j := range ts {
		ml := myLower(j.org)
		require.Equal(t, j.r, ml, "At %d %s ≠ %s", i, j.r, ml)
	}
}
