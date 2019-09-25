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
	"time"
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
					fromProxy: &proxy.Operation{Command: proxy.Open},
					okf:       falseRulesEval,
				},
				{
					toApi: &mng.Cmd{
						Manager: "sessions",
						Cmd:     mng.Open,
						Cred:    &mng.Credentials{User: "user0", Pass: "pass0"},
					},
					okf: okCmd,
				},
			},
		},
		{
			"10.0.0.1",
			[]req{
				{
					toApi: &mng.Cmd{
						Manager: "sessions",
						Cmd:     mng.Open,
						Cred: &mng.Credentials{
							User: "user1",
							Pass: "pass1",
						},
					},
					fromProxy: &proxy.Operation{Command: proxy.Open},
					okf:       okCmdRes,
				},
			},
		},
	}
	rc := make(chan reqBool, len(clients)+1)
	inf := func(i int) {
		go func() {
			inf0 := func(j int) {
				req := clients[i].reqs[j]
				c := req.toApi
				if c != nil {
					c.IP = clients[i].ip
					cmf(c)
				}
				op := req.fromProxy
				var res *proxy.Result
				if op != nil {
					op.IP = clients[i].ip
					res = ctl(op)
				}
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
	toApi     *mng.Cmd
	fromProxy *proxy.Operation
	okf       func(*mng.Cmd, *proxy.Result) bool
}

func okCmd(c *mng.Cmd, r *proxy.Result) (ok bool) {
	ok = c.Err == nil
	return
}

func okCmdRes(c *mng.Cmd, r *proxy.Result) (ok bool) {
	ok = c.Err == nil && r.Error == nil
	return
}

func falseRulesEval(c *mng.Cmd, r *proxy.Result) (ok bool) {
	var fr *mng.ForbiddenByRulesErr
	ok = errors.As(r.Error, &fr)
	return
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
		user1 = "pass1"
	[mapDB.userGroup]
		user0 = ["group0"]
`

func TestServe(t *testing.T) {
	// server configuration
	home, e := os.UserHomeDir()
	require.NoError(t, e)
	fs := afero.NewMemMapFs()
	e = afero.WriteFile(fs, path.Join(home, confDir, confFile),
		[]byte(cfgExample), 0644)
	require.NoError(t, e)
	// managers configuration
	cfile, _, e := mng.ConfPath()
	require.NoError(t, e)
	e = afero.WriteFile(fs, cfile, []byte(cfg), 0644)
	require.NoError(t, e)

	go Serve(fs)

	cl := &PMClient{Fs: fs, PostCmd: PostCmd}
	var dr *mng.DiscoverRes
	times, lapse := 50, 200*time.Millisecond
	ib := func(i int) (ok bool) {
		time.Sleep(lapse)
		dr, e = cl.discoverC("https://localhost:4443", "")
		ok = e == nil
		return
	}
	ok, _ := alg.BLnSrch(ib, times)
	if ok {
		expected := &mng.DiscoverRes{
			Result: "false",
			MatchMng: map[string]*mng.MatchType{
				"sessions": &mng.MatchType{
					Match: false,
					Type:  mng.SessionIPMK,
				},
			},
		}
		require.Equal(t, expected, dr)
	}
}
