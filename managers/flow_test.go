package managers

import (
	alg "github.com/lamg/algorithms"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

func TestExec(t *testing.T) {
	m := &manager{mngs: new(sync.Map)}
	ms := []struct {
		name string
		f    CmdF
	}{
		{
			"a",
			func(c *Cmd) (term bool) {
				term = c.User != ""
				if !term {
					c.Manager = "ipUser"
				}
				return
			},
		},
		{
			"ipUser",
			func(c *Cmd) (term bool) {
				c.User, term = "coco", true
				return
			},
		},
	}

	inf := func(i int) {
		m.add(ms[i].name, ms[i].f)
	}
	alg.Forall(inf, len(ms))
	c := &Cmd{Manager: "a"}
	m.exec(c)
	require.Equal(t, "a", c.Manager)
	require.Equal(t, "coco", c.User)
}
