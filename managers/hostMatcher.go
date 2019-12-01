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
	"regexp"
)

type hostMatcher struct {
	Name    string `toml:"name"`
	Pattern string `toml:"pattern"`

	pattern *regexp.Regexp
}

func (m *hostMatcher) init() (e error) {
	m.pattern, e = regexp.Compile(m.Pattern)
	return
}

func (m *hostMatcher) exec(c *Cmd) {
	if c.Cmd == Match {
		ok := m.pattern.MatchString(c.rqp.URL)
		c.interp[m.Name] = &MatchType{Match: ok, Type: HostMatcher}
	}
}
