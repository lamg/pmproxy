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
	alg "github.com/lamg/algorithms"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"net/url"
	"testing"
)

func TestLoad(t *testing.T) {
	fs := afero.NewMemMapFs()
	_, _, _, e := Load("", fs)
	require.Error(t, e)
	confPath, confFullDir, e := ConfPath()
	fc := []string{cfg0}
	inf := func(i int) {
		e = afero.WriteFile(fs, confPath, []byte(fc[i]), 0644)
		require.NoError(t, e)
		_, _, _, e := Load(confFullDir, fs)
		require.NoError(t, e)
	}
	alg.Forall(inf, len(fc))
}

const cfg0 = `
rules = "sessions ∧ down"
admins = ["user0"]

[mapDB]
	name = "map"
	[mapDB.userPass]
		user0 = "pass0"
		user1 = "pass1"
	[mapDB.userGroups]
		user0 = ["group0"]
		user1 = ["group1"]

[[sessionIPM]]
	name = "sessions"
	auth = "map"

[[dwnConsR]]
	name = "down"
	userDBN = "map"
	resetCycle = "168h"
	[dwnConsR.groupQuota]
		group0 = "1 KB"
		group1 = "512 B"
`

func confTest(t *testing.T, conf string) (c CmdF, d *Dialer) {
	fs := afero.NewMemMapFs()
	confPath, fullDir, e := ConfPath()
	require.NoError(t, e)
	e = afero.WriteFile(fs, confPath, []byte(conf), 0644)
	require.NoError(t, e)
	c, d, _, e = Load(fullDir, fs)
	require.NoError(t, e)
	d.Dialer = MockDialerF
	return
}

var od4 = "1.1.1.1:443"

const cfg1 = `
rules = "(range0 ∧ iface0) ∨ (range1 ∧ proxy0)"

[[rangeIPM]]
	name = "range0"
	cidr = "10.2.0.0/16"

[[rangeIPM]]
	name = "range1"
	cidr = "10.3.0.0/16"

[[parentProxy]]
	name = "proxy0"
	proxyURL = "socks5://proxy0.org:9050"

[[netIface]]
	name = "iface0"
	iface = "eth0"
`

func TestIfaceAndParent(t *testing.T) {
	proxyURL, e := url.Parse("socks5://proxy0.org:9050")
	require.NoError(t, e)
	cmdf, _ := confTest(t, cfg1)
	cs := []struct {
		c     *Cmd
		proxy *url.URL
		iface string
		match bool
	}{
		{
			c: &Cmd{
				Cmd:     Match,
				Manager: RulesK,
				ip:      "10.1.0.1",
			},
			match: false,
		},
		{
			c: &Cmd{
				Cmd:     Match,
				Manager: RulesK,
				ip:      "10.2.1.1",
			},
			iface: "eth0",
			match: true,
		},
		{
			c: &Cmd{
				Cmd:     Match,
				Manager: RulesK,
				ip:      "10.3.1.1",
			},
			proxy: proxyURL,
			match: true,
		},
	}
	inf := func(i int) {
		cmdf(cs[i].c, cs[i].c.ip)
		require.Equal(t, cs[i].match, cs[i].c.ok)
		require.Equal(t, cs[i].proxy, cs[i].c.parentProxy, "At %d", i)
		require.Equal(t, cs[i].iface, cs[i].c.iface)
	}
	alg.Forall(inf, len(cs))
}
