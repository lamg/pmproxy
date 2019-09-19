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
	"errors"
	pred "github.com/lamg/predicate"
	"github.com/lamg/proxy"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"testing"
)

func TestConnections(t *testing.T) {
	_, ctl := confTest(t)
	res := ctl(&proxy.Operation{
		Command: proxy.Open,
		IP:      ht.DefaultRemoteAddr,
	})
	var fr *ForbiddenByRulesErr
	require.True(t, errors.As(res.Error, &fr))
	require.Equal(t, pred.FalseStr, fr.Result)

	_, ctl, _ = openTest(t)
	res = ctl(&proxy.Operation{
		Command: proxy.Open,
		IP:      ht.DefaultRemoteAddr,
	})
	require.NoError(t, res.Error)
	ctl(&proxy.Operation{
		Command: proxy.Close,
		IP:      ht.DefaultRemoteAddr,
	})
	res = ctl(&proxy.Operation{
		Command: proxy.ReadRequest,
		IP:      ht.DefaultRemoteAddr,
	})
	var nc *NoConnErr
	require.True(t, errors.As(res.Error, &nc))
	require.Equal(t, ht.DefaultRemoteAddr, nc.IP)
}
