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

package pmproxy

import (
	"bytes"
	"encoding/json"
	"errors"
	mng "github.com/lamg/pmproxy/managers"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"testing"
)

func TestUnmarshalErr(t *testing.T) {
	bs, e := json.Marshal(mng.ErrExpired)
	require.NoError(t, e)
	bf := bytes.NewBuffer(bs)
	ne := unmarshalErr(ioutil.NopCloser(bf))
	require.True(t, errors.Is(ne, mng.ErrExpired))
}
