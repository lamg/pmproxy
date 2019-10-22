// Copyright © 2017-2019 Luis Ángel Méndez Gort

// This file is part of PMProxy.

// PMProxy is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.

// PMProxy is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Affero General Public
// License for more details.

// You should have received a copy of the GNU Affero General
// Public License along with PMProxy.  If not, see
// <https://www.gnu.org/licenses/>.

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
	r0 := &MatchType{
		Type:  SpanK,
		Match: false,
	}
	require.True(t, ok0)
	require.Equal(t, r0, v0)
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
