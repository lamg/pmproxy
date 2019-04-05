package pmproxy

import (
	"encoding/json"
	"github.com/BurntSushi/toml"
	pred "github.com/lamg/predicate"
	"github.com/spf13/afero"
	"github.com/spf13/cast"
	"github.com/stretchr/testify/require"
	h "net/http"
	"testing"
	"time"
)

func TestFilterMatch(t *testing.T) {
	hnd := basicConfT(t)
	loginAddr := "192.168.1.1:1919"
	ts := []func(*testResp) testReq{
		func(p *testResp) testReq {
			return discoverTR(t, p, loginAddr)
		},
		func(p *testResp) testReq {
			return loginTR(t, p, loginAddr, 0)
		},
		func(p *testResp) testReq {
			return testReq{
				command: &cmd{
					Cmd:     discover,
					Manager: resourcesK,
				},
				rAddr: loginAddr,
				code:  h.StatusOK,
				bodyOK: func(bs []byte) {
					dr := new(discoverRes)
					e := json.Unmarshal(bs, dr)
					require.NoError(t, e)
					require.Equal(t, dr.Result.String, pred.TrueStr)
				},
			}
		},
	}
	runReqTests(t, ts, hnd)
}

func TestShowMng(t *testing.T) {
	hnd := basicConfT(t)
	ts := []func(*testResp) testReq{
		func(p *testResp) testReq {
			return testReq{
				command: &cmd{
					Manager: resourcesK,
					Cmd:     specKS,
					String:  defaultDwnConsR,
				},
				rAddr: "192.168.1.2:1919",
				code:  h.StatusOK,
				bodyOK: func(bs []byte) {
					require.True(t, len(bs) != 0)
					sp := new(spec)
					e := json.Unmarshal(bs, &sp)
					require.NoError(t, e)
					require.Equal(t, sp.ProxyURL, "http://proxy.com:8080")
				},
			}
		},
	}
	runReqTests(t, ts, hnd)
}

func TestBasicConf(t *testing.T) {
	pth := confPath()
	fs := afero.NewMemMapFs()
	e := basicConf(pth, fs)
	bs, e := afero.ReadFile(fs, pth)
	require.NoError(t, e)
	var mp map[string]interface{}
	m, e := toml.Decode(string(bs), &mp)
	require.NoError(t, e)
	require.True(t, m.IsDefined(rulesK))
	si := mp[sessionIPMK]
	sl := cast.ToSlice(si)
	require.NotNil(t, sl)
	sm := new(sessionIPM)
	e = sm.fromMap(sl[0])
	require.NoError(t, e)
	require.Equal(t, sm.name, "sessions")
}

func basicConfT(t *testing.T) (hnd h.HandlerFunc) {
	pth := confPath()
	fs := afero.NewMemMapFs()
	basicConf(pth, fs)
	ok, e := afero.Exists(fs, pth)
	require.True(t, ok && e == nil)
	c, e := newConf(fs)
	require.NoError(t, e)
	res := c.res
	res.cr.expiration = time.Second
	_, ifh, e := newHnds(c)
	require.NoError(t, e)
	hnd = ifh.serveHTTP
	return
}
