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
	pred "github.com/lamg/predicate"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"testing"
)

func TestExec(t *testing.T) {
	m := newManager()
	m.mngs.Store(ipUserMng, newIpUser().exec)
	sm := &sessionIPM{
		Name: "sessions",
	}
	rs := &rules{
		predicate: &pred.Predicate{
			Operator: pred.Term, String: sm.Name,
		},
	}
	m.mngs.Store(sm.Name, sm.exec)
	m.mngs.Store(RulesK, rs.exec)
	ts := []struct {
		c  *Cmd
		ok bool
	}{
		{
			c: &Cmd{
				Cmd:     Match,
				Manager: RulesK,
				IP:      ht.DefaultRemoteAddr,
			},
			ok: false,
		},
	}
	inf := func(i int) {
		m.exec(ts[i].c)
		require.Equal(t, ts[i].ok, ts[i].c.Ok)
	}
	alg.Forall(inf, len(ts))
}
