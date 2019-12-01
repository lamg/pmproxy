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
	alg "github.com/lamg/algorithms"
	pred "github.com/lamg/predicate"
	"github.com/lamg/proxy"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"testing"
)

func TestHostMatcher(t *testing.T) {
	_, dlr := confTest(t, hostMatcherCfg)
	ts := []struct {
		url string
		fe  func(error)
	}{
		{
			url: "https://facebook.com",
			fe: func(x error) {
				var fr *ForbiddenByRulesErr
				require.Error(t, x)
				require.True(t, errors.As(x, &fr))
				require.Equal(t, pred.FalseStr, fr.Result)
			},
		},
		{url: "https://google.com"},
		{url: "https://youtube.com"},
	}
	inf := func(i int) {
		rqp := &proxy.ReqParams{
			IP:  ht.DefaultRemoteAddr,
			URL: ts[i].url,
		}
		ctx := context.WithValue(context.Background(),
			proxy.ReqParamsK, rqp)
		_, e := dlr.DialContext(ctx, tcp, "https://facebook.com")
		require.Equal(t, ts[i].fe == nil, e == nil, "At %d", i)
		if ts[i].fe != nil {
			ts[i].fe(e)
		}
	}
	alg.Forall(inf, len(ts))
}

const hostMatcherCfg = `
	rules = "(h0 ∨ h1) ∧ ¬h2"

	[[hostMatcher]]
		name = "h0"
		pattern = "google\\.com$"
	
	[[hostMatcher]]
		name = "h1"
		pattern = "youtube\\.com$"
	
	[[hostMatcher]]
		name = "h2"
		pattern = "facebook\\.com"
`

func TestHostWithoutConsumption(t *testing.T) {
	cmf, _ := confTest(t, hostNoConsConf)
	open := &Cmd{
		Manager: "sessions",
		Cmd:     Open,
		Cred:    &Credentials{User: "user0", Pass: "pass0"},
	}
	cmf(open, ht.DefaultRemoteAddr)
	require.NoError(t, open.err)
	req := &Cmd{
		Manager: connectionsMng,
		Cmd:     Open,
		rqp: &proxy.ReqParams{
			IP:  ht.DefaultRemoteAddr,
			URL: "14ymedio.cu",
		},
	}
	cmf(req, ht.DefaultRemoteAddr)
	require.NoError(t, req.err)
	require.Equal(t, 0, len(req.consR))

	req0 := &Cmd{
		Manager: connectionsMng,
		Cmd:     Open,
		rqp: &proxy.ReqParams{
			IP:  ht.DefaultRemoteAddr,
			URL: "google.com",
		},
	}
	cmf(req0, ht.DefaultRemoteAddr)
	require.Equal(t, []string{"down"}, req0.consR)
}

const hostNoConsConf = `
	rules = "sessions ∧ (puntoCu ∨ down)"

	[[hostMatcher]]
		name = "puntoCu"
		pattern = "\\.cu$"
	
	[[dwnConsR]]
		name = "down"
		userDBN = "map"
		resetCycle = "24h"
		[dwnConsR.GroupQuota]
			group0 = "10 GB"
	
	[[sessionIPM]]
		name = "sessions"
		auth = "map"
	
	[mapDB]
		name = "map"
		[mapDB.userPass]
			user0 = "pass0"
		[mapDB.userGroups]
			user0 = ["group0"]
`
