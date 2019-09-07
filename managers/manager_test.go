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
