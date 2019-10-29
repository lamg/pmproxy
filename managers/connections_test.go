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
	"context"
	"errors"
	pred "github.com/lamg/predicate"
	"github.com/lamg/proxy"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"testing"
	"time"
)

func TestConnections(t *testing.T) {
	_, dlr := confTest(t, cfg0)
	rqp := &proxy.ReqParams{IP: ht.DefaultRemoteAddr}
	ctx := context.WithValue(context.Background(),
		proxy.ReqParamsK, rqp)
	_, e := dlr.DialContext(ctx, tcp, od4)
	var fr *ForbiddenByRulesErr
	require.True(t, errors.As(e, &fr))
	require.Equal(t, pred.FalseStr, fr.Result)

	cmf, dlr, jtk := openTest(t)
	n, e := dlr.DialContext(ctx, tcp, od4)
	require.NoError(t, e)
	n.Close()
	chkClientConn := &Cmd{
		Manager: connectionsMng,
		Cmd:     readRequest,
		IP:      ht.DefaultRemoteAddr,
	}
	cmf(chkClientConn)
	require.NoError(t, chkClientConn.Err)
	require.True(t, len(chkClientConn.consR) != 0)
	c := &Cmd{
		Cmd:     Close,
		Manager: "sessions",
		Secret:  jtk,
		IP:      ht.DefaultRemoteAddr,
	}
	cmf(c)
	require.NoError(t, c.Err)
	bs := make([]byte, 10)
	_, e = n.Read(bs)
	var nc *NoConnErr
	require.True(t, errors.As(e, &nc))
	require.Equal(t, ht.DefaultRemoteAddr, nc.IP)
}

func BenchmarkConnections(b *testing.B) {
	fs := afero.NewMemMapFs()
	confPath, fullDir, e := ConfPath()
	require.NoError(b, e)
	e = afero.WriteFile(fs, confPath, []byte(cfg0), 0644)
	require.NoError(b, e)
	cmf, dlr, _, e := Load(fullDir, fs)
	dlr.Dialer = MockDialerF
	require.NoError(b, e)

	open := &Cmd{
		Manager: "sessions",
		Cmd:     Open,
		IP:      ht.DefaultRemoteAddr,
		Cred:    &Credentials{User: "user0", Pass: "pass0"},
	}
	cmf(open)
	require.NoError(b, open.Err)
	rqp := &proxy.ReqParams{IP: ht.DefaultRemoteAddr}

	ctx := context.WithValue(context.Background(),
		proxy.ReqParamsK, rqp)
	b.ResetTimer()
	_, e = dlr.DialContext(ctx, tcp, od4)
	require.NoError(b, e)
}

func BenchmarkBasicConnection(b *testing.B) {
	dlr := MockDialerF("eth0", time.Second)
	dlr.Dial(tcp, od4)
}
