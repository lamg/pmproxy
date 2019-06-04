package managers

import (
	"fmt"
	alg "github.com/lamg/algorithms"
	"github.com/lamg/proxy"
	"sync"
	"time"
)

type manager struct {
	mngs *sync.Map
}

type Cmd struct {
	Cmd       string           `json:"cmd"`
	User      string           `json:"user"`
	Manager   string           `json:"manager"`
	Secret    string           `json:"secret"`
	IsAdmin   bool             `json:"isAdmin"`
	Cred      *Credentials     `json:"c.Errd"`
	String    string           `json:"string"`
	Uint64    uint64           `json:"uint64"`
	Groups    []string         `json:"groups"`
	Ok        bool             `json:"ok"`
	IP        string           `json:"ip"`
	Data      []byte           `json:"data"`
	Err       error            `json:"-"`
	Operation *proxy.Operation `json:"-"`
	Result    *proxy.Result    `json:"-"`

	defKeys []string
}

type Credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

func (c *Cmd) defined(key string) (ok bool) {
	ib := func(i int) bool { return c.defKeys[i] == key }
	ok, _ = alg.BLnSrch(ib, len(c.defKeys))
	return
}

type CmdF func(*Cmd) bool

func newmanager(exp time.Duration) (m *manager, e error) {
	m = &manager{mngs: new(sync.Map)}
	iu := newIpUser()
	cr, e := newCrypt(exp)
	if e == nil {
		m.add(ipUserMng, iu.exec)
		m.add(cryptMng, cr.exec)
	}
	return
}

func (m *manager) add(name string, f CmdF) {
	m.mngs.Store(name, f)
	return
}

const (
	Skip       = "skip"
	Get        = "get"
	Set        = "set"
	HandleConn = "handleConn"
	Show       = "show"
)

/*
- each command when executed can be terminal or not. If not terminal,
it means it must be executed by the manager now at Cmd.manager. If
terminal it most be executed by the manager who originated it. Each
manager must deal correctly with incoming and outgoing commands,
according information present in them. The field Cmd.Object support
storing and reading information produced by a sequence of executions.
*/

type mngCmd struct {
	mng string
	cmd string
}

func (m *manager) exec(c *Cmd) {
	var mngs []*mngCmd
	term, prev := m.execStep(c)
	if !term {
		mngs = []*mngCmd{prev}
	}
	for len(mngs) != 0 && c.Err == nil {
		term, prev = m.execStep(c)
		if term {
			last := len(mngs) - 1
			next := mngs[last]
			mngs = mngs[:last]
			c.Manager = next.mng
			c.Cmd = next.cmd
		} else {
			mngs = append(mngs, prev)
		}
	}
}

func (m *manager) execStep(c *Cmd) (term bool, prev *mngCmd) {
	v, ok := m.mngs.Load(c.Manager)
	prev = &mngCmd{mng: c.Manager, cmd: c.Cmd}
	if ok {
		term = v.(CmdF)(c)
	} else {
		c.Err = fmt.Errorf("manager '%s' not found", c.Manager)
	}
	return
}

func (m *manager) delete(name string) (e error) {
	m.mngs.Delete(name)
	return
}
