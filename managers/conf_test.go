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
	alg "github.com/lamg/algorithms"
	"github.com/lamg/proxy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestLoad(t *testing.T) {
	fs := afero.NewMemMapFs()
	_, _, _, e := Load("", fs)
	require.Error(t, e)
	confPath, confFullDir, e := ConfPath()
	fc := []string{cfg0}
	inf := func(i int) {
		e = afero.WriteFile(fs, confPath, []byte(fc[i]), 0644)
		require.NoError(t, e)
		_, _, _, e := Load(confFullDir, fs)
		require.NoError(t, e)
	}
	alg.Forall(inf, len(fc))
}

const cfg0 = `
rules = "sessions"

[mapDB]
	name = "map"
	[mapDB.userPass]
		user0 = "pass0"

[sessionIPM]
	name = "sessions"
	auth = "map"

[dwnConsR]
	name = "down"
`

func confTest(t *testing.T) (c CmdF, p proxy.ConnControl) {
	fs := afero.NewMemMapFs()
	confPath, fullDir, e := ConfPath()
	require.NoError(t, e)
	e = afero.WriteFile(fs, confPath, []byte(cfg0), 0644)
	require.NoError(t, e)
	c, p, _, e = Load(fullDir, fs)
	require.NoError(t, e)
	return
}
