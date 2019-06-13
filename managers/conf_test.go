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
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNewConf(t *testing.T) {
	c := new(conf)
	e := toml.Unmarshal([]byte(testCfg), c)
	require.NoError(t, e)
	pc := &conf{
		Admins: []string{"coco", "pepe"},
		ProxyIface: []proxyIfaceMng{
			{Name: "tubo0", Iface: "eth0"},
			{Name: "tubo1", Iface: "eth1"},
		},
	}
	require.Equal(t, pc, c)
}

const testCfg = `
admins = ["coco", "pepe"]

[[proxyIface]]
	name = "tubo0"
	iface = "eth0"

[[proxyIface]]
	name = "tubo1"
	iface = "eth1"
`
