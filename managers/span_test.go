package managers

import (
	"github.com/pelletier/go-toml"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestSpan(t *testing.T) {
	c := new(conf)
	e := toml.Unmarshal([]byte(spanConf), c)
	require.NoError(t, e)
	m, e := time.Parse(time.RFC3339, "2006-01-02T15:05:05-04:00")
	s := c.TimeSpan[0]
	s.now = func() time.Time { return m }
	n := &Cmd{Cmd: Match, interp: make(map[string]*MatchType)}
	s.exec(n)
	require.True(t, n.Ok)
	v, ok := n.interp[s.Name]
	require.True(t, ok)
	r := &MatchType{
		Type:  SpanK,
		Match: true,
	}
	require.Equal(t, r, v)

	fs := afero.NewMemMapFs()
	confPath, fullDir, e := ConfPath()
	require.NoError(t, e)
	e = afero.WriteFile(fs, confPath, []byte(spanConf), 0644)
	require.NoError(t, e)
	cmdf, _, _, e := Load(fullDir, fs)
	require.NoError(t, e)
	n0 := &Cmd{
		Cmd:     Match,
		Manager: s.Name,
		interp:  make(map[string]*MatchType),
	}
	cmdf(n0)
	v0, ok0 := n0.interp[s.Name]
	require.True(t, ok0)
	require.Equal(t, r, v0)
}

const spanConf = `
rules = "night"
[[timeSpan]]
	name = "night"
	[timeSpan.span]
		start=2006-01-02T15:04:05-04:00
		active = "5m"
		total = "10m"
		infinite = true
`
