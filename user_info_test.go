package pmproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestElementOf(t *testing.T) {
	a, b, c := []string{"a", "b", "c"}, []string{"c"}, []string{"C"}
	aok, i := hasElementOf(a, b)
	require.True(t, aok && i == 1)
	cok, j := hasElementOf(a, c)
	require.True(t, !cok && j == 1)
}
