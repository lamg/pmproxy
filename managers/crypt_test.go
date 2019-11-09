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
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestExpiration(t *testing.T) {
	cr, e := newCrypt(time.Minute)
	require.NoError(t, e)
	nw := time.Now()
	jwt.TimeFunc = func() (n time.Time) {
		n = nw.Add(5 * time.Minute)
		nw = n
		return
	}
	user := "user"
	c := &Cmd{Cmd: encrypt, loggedBy: &userSessionIPM{user: user}}
	cr.exec(c)
	require.NoError(t, c.err)
	c0 := &Cmd{Cmd: decrypt, Secret: string(c.data)}
	cr.exec(c0)
	require.True(t, errors.Is(c0.err, ErrExpired), "%v", e)
	c1 := &Cmd{
		Cmd:      Renew,
		Secret:   c0.Secret,
		loggedBy: &userSessionIPM{user: user},
	}
	cr.exec(c1)
	require.NoError(t, c1.err)
	require.NotEqual(t, 0, len(c1.data))
	require.NotEqual(t, c0.Secret, string(c1.data))
	jwt.TimeFunc = time.Now
	c1.Cmd = Check
	cr.exec(c1)
	require.Equal(t, user, string(c1.data))
}
