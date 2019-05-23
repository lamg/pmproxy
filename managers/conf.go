package managers

import (
	"github.com/lamg/proxy"
	"github.com/pelletier/go-toml"
	"github.com/spf13/afero"
)

func Load(fs afero.Fs, t *toml.Tree) (cmdChan CmdF,
	ctl proxy.ConnControl, e error) {
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
	return
}
