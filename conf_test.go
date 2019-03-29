package pmproxy

import (
	"github.com/BurntSushi/toml"
	"github.com/spf13/afero"
	"github.com/spf13/cast"
	"github.com/stretchr/testify/require"
	h "net/http"
	"testing"
	"time"
)

func TestConf(t *testing.T) {
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
