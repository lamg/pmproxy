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
	cmf, _ := confTest(t)
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
		"down":     &MatchType{Match: true, Type: DwnConsRK},
	}
	require.Equal(t, interp, dr.MatchMng)
	require.Equal(t, 0, len(c.consR))
}
