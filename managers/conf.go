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

/*
# Configuration

This file loads the main managers: the resource matcher and the connection handler.
*/

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
				Manager:   connectionsMng,
				Cmd:       HandleConn,
				Operation: o,
				Result:    new(proxy.Result),
			}
			cmdChan(c)
			r = c.Result
			return
		}
	}
	return
}

// TODO see how TOML deserialization works for map[string]object

type conf struct {
	JWTExpiration time.Duration `toml:"jwtExpiration"`
	Admins        []string      `toml:"admins"`
	DwnConsR      map[string]dwnConsR
	BwConsR       map[string]bwConsR
	AdDB          map[string]adDB
	MapDB         map[string]mapDB
	GroupIPM      map[string]groupIPM
	ProxyIface    map[string]proxyIfaceMng
	ProxyURL      map[string]proxyURLMng
	RangeIPM      map[string]rangeIPM
	SessionIPM    map[string]sessionIPM
}
