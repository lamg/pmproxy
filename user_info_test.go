package pmproxy

import (
	"bytes"
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

func TestAdmNames(t *testing.T) {
	bf := bytes.NewBufferString(conf)
	c, e := ParseConf(bf)
	require.Nil(t, e)
	ok, _ := elementOf(c.AdmNames, "Adm")
	require.True(t, ok)
}
