package pmproxy

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCryptoUser(t *testing.T) {
	hd := make(map[string][]string)
	j := NewJWTCrypt()
	_, e := j.user(hd)
	require.Equal(t, HeaderErr(), e)
}
