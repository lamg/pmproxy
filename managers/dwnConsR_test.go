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
	"github.com/c2h5oh/datasize"
	"github.com/pelletier/go-toml"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDwnConsR(t *testing.T) {
	bts0 := 1024 * datasize.MB
	str := bts0.HR()

	bts := new(datasize.ByteSize)
	e := bts.UnmarshalText([]byte(cleanHumanReadable(str)))
	require.NoError(t, e)

	c := new(conf)
	e = toml.Unmarshal([]byte(cfg0), c)
	require.NoError(t, e)
	require.Equal(t, "1 GB", c.DwnConsR.GroupQuota["group0"])
	fs := afero.NewMemMapFs()
	e = c.DwnConsR.init(fs, "")
	require.NoError(t, e)
	q := c.DwnConsR.quota("user0", []string{"group0"})
	require.Equal(t, uint64(datasize.GB), q)
}
