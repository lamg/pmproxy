package pmproxy

import (
	"errors"
	alg "github.com/lamg/algorithms"
	mng "github.com/lamg/pmproxy/managers"
	"github.com/lamg/proxy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"os"
	"path"
	"testing"
)

func TestConf(t *testing.T) {
	home, e := os.UserHomeDir()
	require.NoError(t, e)
	fs := afero.NewMemMapFs()
	e = afero.WriteFile(fs, path.Join(home, confDir, confFile),
		[]byte(cfgExample), 0644)
	require.NoError(t, e)
	p, e := load(fs)
	require.NoError(t, e)
	require.NotNil(t, p.Proxy)
	require.NotNil(t, p.Api)
}

var cfgExample = `
[api]
	httpsCert="cert.pem"
	httpsKey="key.pem"
	webStaticFilesDir="staticFiles"
	persistInterval="5m"
	[api.server]
		readTimeout="30s"
		writeTimeout="20s"
		addr=":4443"
		fastOrStd=true

[proxy]
	dialTimeout="10s"
	[proxy.server]
		readTimeout="30s"
		writeTimeout="20s"
		addr=":8081"
		fastOrStd=true
`

func TestConcurrency(t *testing.T) {
	fs := afero.NewMemMapFs()
	cfile, _, e := mng.ConfPath()
	require.NoError(t, e)
	e = afero.WriteFile(fs, cfile, []byte(cfg), 0644)
	require.NoError(t, e)
	cmf, ctl, _, e := mng.Load("", fs)
	require.NoError(t, e)
	clients := []struct {
		ip   string
		reqs []req
	}{
		{
			ht.DefaultRemoteAddr,
			[]req{
				{
					toApi:     mng.Cmd{},
					fromProxy: proxy.Operation{Command: proxy.Open},
					okf: func(c *mng.Cmd, r *proxy.Result) (ok bool) {
						var fr *mng.ForbiddenByRulesErr
						ok = errors.As(r.Error, &fr)
						var nc *mng.ManagerErr
						ok = ok && errors.As(c.Err, &nc)
						return
					},
				},
			},
		},
	}
	rc := make(chan reqBool, len(clients)+1)
	inf := func(i int) {
		go func() {
			inf0 := func(j int) {
				req := clients[i].reqs[j]
				c := &req.toApi
				c.IP = clients[i].ip
				cmf(c)
				op := &req.fromProxy
				op.IP = c.IP
				res := ctl(op)
				ok := req.okf(c, res)
				rc <- reqBool{i: i, j: j, ok: ok}
			}
			alg.Forall(inf0, len(clients[i].reqs))
		}()
	}
	alg.Forall(inf, len(clients))
	for k := range rc {
		require.True(t, k.ok, "At i:%d j:%d", k.i, k.j)
		if k.i == len(clients)-1 {
			break
		}
	}
}

type reqBool struct {
	ok   bool
	i, j int
}

type req struct {
	toApi     mng.Cmd
	fromProxy proxy.Operation
	okf       func(*mng.Cmd, *proxy.Result) bool
}

const cfg = `
rules = "sessions ∧ down"

[sessionIPM]
	name = "sessions"
	auth = "map"

[dwnConsR]
	name = "down"
	userDBN = "map"
	resetCycle = "1h"
	[dwnConsR.quotaMap]
		group0 = "1 MB"

[mapDB]
	name = "map"
	[mapDB.userPass]
		user0 = "pass0"
	[mapDB.userGroup]
		user0 = ["group0"]
`
