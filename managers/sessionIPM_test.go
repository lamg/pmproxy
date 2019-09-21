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
	"github.com/lamg/proxy"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"testing"
)

func TestSessionIPMOpen(t *testing.T) {
	cmf, ctl, jtk := openTest(t)
	cm := &Cmd{
		Manager: "sessions",
		Cmd:     Close,
		Secret:  jtk,
		IP:      ht.DefaultRemoteAddr,
	}
	cmf(cm)
	require.NoError(t, cm.Err)
	res := ctl(&proxy.Operation{
		Command: proxy.ReadRequest,
		IP:      ht.DefaultRemoteAddr,
		Amount:  14,
	})
	var nc *NoConnErr
	require.True(t, errors.As(res.Error, &nc))
	require.Equal(t, ht.DefaultRemoteAddr, nc.IP)
}

func openTest(t *testing.T) (cmf CmdF, ctl proxy.ConnControl,
	jtk string) {
	cmf, ctl = confTest(t)
	open := &Cmd{
		Manager: "sessions",
		Cmd:     Open,
		Cred:    &Credentials{User: "user0", Pass: "pass0"},
		IP:      ht.DefaultRemoteAddr,
	}
	cmf(open)
	require.NoError(t, open.Err)
	jtk = string(open.Data)
	return
}

func TestSessionIPMCheck(t *testing.T) {
	cmf, _, jtk := openTest(t)
	check := &Cmd{
		Manager: "sessions",
		Cmd:     Check,
		Secret:  jtk,
		IP:      ht.DefaultRemoteAddr,
	}
	cmf(check)
	require.NoError(t, check.Err)
}
