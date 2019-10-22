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

type proxyIfaceMng struct {
	Name  string `toml:"name"`
	Iface string `toml:"iface"`
}

func (p *proxyIfaceMng) exec(c *Cmd) {
	if c.Cmd == Match {
		c.Ok, c.interp[p.Name], c.iface =
			true, &MatchType{Type: IfaceK, Match: true}, p.Iface
	}
	return
}
