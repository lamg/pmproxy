package managers

import (
	"fmt"
	"sync"
)

type Manager struct {
	mngs *sync.Map
}

type Cmd struct {
	Cmd        string                 `json:"cmd"`
	User       string                 `json:"user"`
	Manager    string                 `json:"manager"`
	RemoteAddr string                 `json:"remoteAddr"`
	Secret     string                 `json:"secret"`
	IsAdmin    bool                   `json:"isAdmin"`
	Cred       *Credentials           `json:"cred"`
	String     string                 `json:"string"`
	Uint64     uint64                 `json:"uint64"`
	Object     map[string]interface{} `json:"object"`
	bs         []byte
	e          error
}

type Credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type CmdF func(*Cmd) bool

func (m *Manager) Add(name string, f CmdF) {
	m.mngs.Store(name, f)
	return
}

const (
	Skip = "skip"
)

/*
- each command when executed can be terminal or not. If not terminal,
it means it must be executed by the manager now at Cmd.Manager. If
terminal it most be executed by the manager who originated it. Each
manager must deal correctly with incoming and outgoing commands,
according information present in them. The field Cmd.Object support
storing and reading information produced by a sequence of executions.
*/

func (m *Manager) Exec(c *Cmd) {
	mngs := []string{}
	term, prev := m.exec(c)
	if !term {
		mngs = []string{prev}
	}
	for len(mngs) != 0 && c.e == nil {
		term, prev = m.exec(c)
		if term {
			c.Manager = mngs[len(mngs)-1]
			mngs = mngs[:len(mngs)-1]
		} else {
			mngs = append(mngs, prev)
		}
	}
}

func (m *Manager) exec(c *Cmd) (term bool, prev string) {
	v, ok := m.mngs.Load(c.Manager)
	prev = c.Manager
	if ok {
		term = v.(CmdF)(c)
	} else {
		c.e = fmt.Errorf("Manager '%s' not found", c.Manager)
	}
	return
}

func (m *Manager) Delete(name string) (e error) {
	m.mngs.Delete(name)
	return
}
