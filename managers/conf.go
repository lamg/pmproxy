package managers

import (
	"github.com/lamg/proxy"
	"github.com/pelletier/go-toml"
	"github.com/spf13/afero"
	"time"
)

func Load(fs afero.Fs, t *toml.Tree) (cmdChan CmdF,
	ctl proxy.ConnControl, e error) {
	// TODO
	m, e := newManager(time.Second)
	if e == nil {
		cmdChan = m.exec
		ctl = func(o *proxy.Operation) (r *proxy.Result) {
			c := &Cmd{
				Manager:   "connections",
				Cmd:       HandleConn,
				Operation: o,
			}
			cmdChan(c)
			r = c.Result
			return
		}
	}
	return
}
