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
	"github.com/stretchr/testify/require"
	h "net/http"
	ht "net/http/httptest"
	"testing"
)

func TestLogin(t *testing.T) {
	c, e := newConf()
	require.NoError(t, e)
	_, ifh, e := newHnds(c)
	require.NoError(t, e)
	loginReq := &credentials{User: user0, Pass: pass0}
	bs, e := json.Marshal(loginReq)
	require.NoError(t, e)
	w, r := ht.NewRecorder(),
		ht.NewRequest(h.MethodPost, apiAuth, bytes.NewBuffer(bs))
	ifh.serveHTTP(w, r)
	require.Equal(t, h.StatusOK, w.Code)
	secr := w.Body.String()
	require.NotEmpty(t, secr)
	t.Log(secr)
}
