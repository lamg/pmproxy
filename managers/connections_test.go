package managers

import (
	"github.com/lamg/proxy"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"testing"
)

func TestConnections(t *testing.T) {
	//TODO
	cmf, ctl := confTest(t)
	res := ctl(&proxy.Operation{
		Command: proxy.Open,
		IP:      ht.DefaultRemoteAddr,
	})
	require.Error(t, res.Error)
	cm := &Cmd{
		Manager: "sessions",
		Cmd:     Open,
		Cred:    &Credentials{User: "user0", Pass: "pass0"},
		IP:      ht.DefaultRemoteAddr,
	}
	cmf(cm)
	require.NoError(t, cm.Err)
	res = ctl(&proxy.Operation{
		Command: proxy.Open,
		IP:      ht.DefaultRemoteAddr,
	})
	require.NoError(t, res.Error)
}
