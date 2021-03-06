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
	"context"
	"errors"
	pred "github.com/lamg/predicate"
	"github.com/lamg/proxy"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"testing"
)

func TestSessionIPMOpen(t *testing.T) {
	cmf, dlr, jtk := openTest(t)
	cm := &Cmd{
		Manager: "sessions",
		Cmd:     Close,
		Secret:  jtk,
	}
	cmf(cm, ht.DefaultRemoteAddr)
	require.NoError(t, cm.err)
	rqp := &proxy.ReqParams{IP: ht.DefaultRemoteAddr}
	ctx := context.WithValue(context.Background(), proxy.ReqParamsK,
		rqp)
	_, e := dlr.DialContext(ctx, tcp, od4)
	var nc *ForbiddenByRulesErr
	require.True(t, errors.As(e, &nc))
	require.Equal(t, pred.FalseStr, nc.Result)
}

func openTest(t *testing.T) (cmf CmdF, dlr *Dialer,
	jtk string) {
	cmf, dlr = confTest(t, cfg0)
	open := &Cmd{
		Manager: "sessions",
		Cmd:     Open,
		Cred:    &Credentials{User: "user0", Pass: "pass0"},
	}
	cmf(open, ht.DefaultRemoteAddr)
	require.NoError(t, open.err)
	jtk = string(open.data)
	return
}

func TestSessionIPMCheck(t *testing.T) {
	cmf, _, jtk := openTest(t)
	check := &Cmd{
		Manager: "sessions",
		Cmd:     Check,
		Secret:  jtk,
	}
	cmf(check, ht.DefaultRemoteAddr)
	require.NoError(t, check.err)
}
