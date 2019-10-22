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
		IP:      ht.DefaultRemoteAddr,
	}
	cmf(c)
	require.NoError(t, c.Err)
	dr := new(DiscoverRes)
	e := json.Unmarshal(c.Data, dr)
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
		IP:      ht.DefaultRemoteAddr,
	}
	cmf(open)
	require.NoError(t, open.Err)
	cmf(c)
	e = json.Unmarshal(c.Data, dr)
	interp["sessions"].Match = true
	interp["down"] = &MatchType{Type: DwnConsRK, Match: true}
	require.Equal(t, interp, dr.MatchMng)
	require.Equal(t, []string{"down"}, c.consR)
}
