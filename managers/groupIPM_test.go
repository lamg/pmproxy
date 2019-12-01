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

func TestGroupIPM(t *testing.T) {
	cmf, dlr := confTest(t, confGroupIPM)
	open := &Cmd{
		Manager: "s0",
		Cmd:     Open,
		Cred:    &Credentials{User: "user1", Pass: "pass1"},
	}
	cmf(open, ht.DefaultRemoteAddr)
	require.NoError(t, open.err)

	rqp := &proxy.ReqParams{IP: ht.DefaultRemoteAddr}
	ctx := context.WithValue(context.Background(), proxy.ReqParamsK,
		rqp)
	_, e := dlr.DialContext(ctx, tcp, od4)
	var nc *ForbiddenByRulesErr
	require.Error(t, e)
	require.True(t, errors.As(e, &nc), "%s", e.Error())
	require.Equal(t, pred.FalseStr, nc.Result)

	open1 := &Cmd{
		Manager: "s0",
		Cmd:     Open,
		Cred:    &Credentials{User: "user0", Pass: "pass0"},
	}
	cmf(open1, ht.DefaultRemoteAddr)
	require.NoError(t, open.err)
	rqp1 := &proxy.ReqParams{IP: ht.DefaultRemoteAddr}
	ctx1 := context.WithValue(context.Background(), proxy.ReqParamsK,
		rqp1)
	_, e1 := dlr.DialContext(ctx1, tcp, od4)
	require.NoError(t, e1)
}

const confGroupIPM = `
	rules = "s0 ∧ g0 ∧ ¬g1"
	
	[mapDB]
		name = "map"
		[mapDB.userPass]
			user0 = "pass0"
			user1 = "pass1"
		[mapDB.userGroups]
			user0 = ["group0"]
			user1 = ["group0", "group1"]
	
	[[groupIPM]]
		name = "g0"
		group = "group0"
		userDBN = "map"
	
	[[groupIPM]]
		name = "g1"
		group = "group1"
		userDBN = "map"
	
	[[sessionIPM]]
		name = "s0"
		auth = "map"
`
