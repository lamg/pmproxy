package pmproxy

import (
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"testing"
	"time"
)

func TestConnect(t *testing.T) {

	ts, cl, dl := d.testStructs(), d.clock(), d.dialer()
	for i, j := range ts {
		c, e := connect(j.addr, j.spec, p, time.Second, cl, dl)
		require.Equal(t, j.err, e, "At %d", i)
		if e == nil {
			var bs []byte
			bs, e = ioutil.ReadAll(c)
			require.Equal(t, j.content, string(bs), "At %d", i)
		}
	}
}

type testConn struct {
	addrContent map[string]string
}
