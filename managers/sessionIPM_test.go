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
	"github.com/lamg/proxy"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"testing"
)

func TestSessionIPM(t *testing.T) {
	cmf, ctl := confTest(t)
	sm := "sessions"
	cm := &Cmd{
		Manager: sm,
		Cmd:     Open,
		Cred:    &Credentials{User: "user0", Pass: "pass0"},
		IP:      ht.DefaultRemoteAddr,
	}
	cmf(cm)
	require.NoError(t, cm.Err)
	cm.Manager, cm.Cmd = sm, Close
	cmf(cm)
	require.NoError(t, cm.Err)
	res := ctl(&proxy.Operation{
		Command: proxy.ReadRequest,
		IP:      ht.DefaultRemoteAddr,
		Amount:  14,
	})
	require.Error(t, res.Error)
	t.Log(res.Error)
}
