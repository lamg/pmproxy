package pmproxy

import (
	"github.com/c2h5oh/datasize"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUnmarshal(t *testing.T) {
	bts0 := 1024 * datasize.MB
	str := bts0.HR()

	bts := new(datasize.ByteSize)
	e := bts.UnmarshalText([]byte(cleanHumanReadable(str)))
	require.NoError(t, e)
}
