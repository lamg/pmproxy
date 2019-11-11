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
	"encoding/json"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"testing"
)

func TestDiscover(t *testing.T) {
	cmf, _ := confTest(t, cfg0)
	c := &Cmd{
		Manager: RulesK,
		Cmd:     Discover,
	}
	cmf(c, ht.DefaultRemoteAddr)
	require.NoError(t, c.err)
	dr := new(DiscoverRes)
	e := json.Unmarshal(c.data, dr)
	require.NoError(t, e)
	require.Equal(t, "false", dr.Result)
	interp := map[string]*MatchType{
		"sessions": &MatchType{Match: false, Type: SessionIPMK},
	}
	require.Equal(t, interp, dr.MatchMng)
	require.Equal(t, 0, len(c.consR))
	open := &Cmd{
		Manager: "sessions",
		Cmd:     Open,
		Cred:    &Credentials{User: "user0", Pass: "pass0"},
	}
	cmf(open, ht.DefaultRemoteAddr)
	require.NoError(t, open.err)
	cmf(c, ht.DefaultRemoteAddr)
	e = json.Unmarshal(c.data, dr)
	interp["sessions"].Match = true
	interp["down"] = &MatchType{Type: DwnConsRK, Match: true}
	require.Equal(t, interp, dr.MatchMng)
	require.Equal(t, []string{"down"}, c.consR)
}

func TestMultipleSessionIPM(t *testing.T) {
	cmf, _ := confTest(t, cfgMultSIPM)
	open := &Cmd{
		Manager: "s0",
		Cmd:     Open,
		Cred:    &Credentials{User: "user0", Pass: "pass0"},
	}
	cmf(open, ht.DefaultRemoteAddr)
	require.NoError(t, open.err)
	discover := &Cmd{
		Manager: RulesK,
		Cmd:     Discover,
	}
	cmf(discover, ht.DefaultRemoteAddr)
	require.NoError(t, discover.err)
	require.Equal(t, []string{"d0"}, discover.consR)
	dr := new(DiscoverRes)
	e := json.Unmarshal(discover.data, dr)
	require.NoError(t, e)
	require.Equal(t, "true", dr.Result)
	interp := map[string]*MatchType{
		"s0":       &MatchType{Match: true, Type: SessionIPMK},
		"d0":       &MatchType{Match: true, Type: DwnConsRK},
		"sessions": &MatchType{Match: false, Type: SessionIPMK},
	}
	require.Equal(t, interp, dr.MatchMng)
}

var cfgMultSIPM = `
rules = "(sessions ∧ down) ∨ (s0 ∧ d0)"
admins = ["adUser", "user0"]
jwtExpiration = "1m"

[adDB]
	name = "ad"
	addr = "10.1.0.0:636"
	suff = "@pmproxy.org"
	bdn = "dc=pmproxy,dc=org"
	user = "adUser"
	pass = "adPass"


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
	auth = "ad"

[[dwnConsR]]
	name = "down"
	userDBN = "ad"
	resetCycle = "168h"
	[dwnConsR.groupQuota]
		AD-Group = "1 GB"

[[sessionIPM]]
	name = "s0"
	auth = "map"

[[dwnConsR]]
	name = "d0"
	userDBN = "map"
	resetCycle = "24h"
	[dwnConsR.groupQuota]
		group0 = "10 GB"
`
