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
	"encoding/json"
	"errors"
	"github.com/c2h5oh/datasize"
	"github.com/lamg/proxy"
	"github.com/pelletier/go-toml"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"testing"
	"time"
)

func TestDwnConsRInit(t *testing.T) {
	bts0 := 1024 * datasize.MB
	str := bts0.HR()

	bts := new(datasize.ByteSize)
	e := bts.UnmarshalText([]byte(cleanHumanReadable(str)))
	require.NoError(t, e)

	c := new(conf)
	e = toml.Unmarshal([]byte(cfg0), c)
	require.NoError(t, e)
	down := c.DwnConsR[0]
	require.Equal(t, "1 KB", down.GroupQuota["group0"])
	fs := afero.NewMemMapFs()
	consFile := "/" + down.Name + ".json"
	afero.WriteFile(fs, consFile, []byte(testConsMap), 0644)
	e = down.init(fs, "/")
	require.NoError(t, e)
	q := down.quota("user0", []string{"group0"})
	require.Equal(t, uint64(datasize.KB), q)
	cons := down.consumption("user0")
	require.Equal(t, uint64(512), cons)

	// persist test
	nw, e := time.Parse(time.RFC3339, "2019-09-18T00:00:00Z")
	require.NoError(t, e)
	down.now = func() time.Time { return nw }
	e = down.persist()
	require.NoError(t, e)
	bs, e := afero.ReadFile(fs, consFile)
	require.NoError(t, e)
	cmp := new(consMap)
	e = json.Unmarshal(bs, cmp)
	require.NoError(t, e)
	nrd, e := time.Parse(time.RFC3339, "2019-09-14T00:00:00Z")
	require.NoError(t, e)
	require.Equal(t, nrd, cmp.LastReset)
	require.Equal(t, 0, len(cmp.Consumptions))
}

func TestDwnConsRHandleConn(t *testing.T) {
	_, dlr, _ := openTest(t)
	rqp := &proxy.ReqParams{
		IP: ht.DefaultRemoteAddr,
	}
	ctx := context.WithValue(context.Background(), proxy.ReqParamsK,
		rqp)
	c, e := dlr.DialContext(ctx, tcp, od4)
	require.NoError(t, e)
	bs := make([]byte, 1024)
	_, e = c.Read(bs)
	require.NoError(t, e)
	_, e = c.Read(bs)
	var qr *QuotaReachedErr
	require.True(t, errors.As(e, &qr))
	require.Equal(t, "1024 B", qr.Quota)
}

func TestDwnConsRGet(t *testing.T) {
	cmf, _, jtk := openTest(t)
	get := &Cmd{
		Manager: "down",
		Cmd:     Get,
		IP:      ht.DefaultRemoteAddr,
		Secret:  jtk,
	}
	cmf(get)
	require.NoError(t, get.Err)
	ui := new(UserInfo)
	e := json.Unmarshal(get.Data, ui)
	require.NoError(t, e)
	rui := &UserInfo{
		UserName:    "user0",
		Name:        "user0",
		Groups:      []string{"group0"},
		Quota:       "1024 B",
		BytesQuota:  1024,
		BytesCons:   0,
		Consumption: "0 B",
	}
	require.Equal(t, rui, ui)
}

func TestDwnConsRSet(t *testing.T) {
	cmf, _, jtk := openTest(t)
	set := &Cmd{
		Manager: "down",
		Cmd:     Set,
		String:  "user1",
		Uint64:  19,
		IP:      ht.DefaultRemoteAddr,
		Secret:  jtk,
	}
	cmf(set)
	require.NoError(t, set.Err)
	open := &Cmd{
		Manager: "sessions",
		Cmd:     Open,
		Cred:    &Credentials{User: "user1", Pass: "pass1"},
		IP:      "192.168.1.1",
	}
	cmf(open)
	require.NoError(t, open.Err)
	get := &Cmd{
		Manager: "down",
		Cmd:     Get,
		IP:      open.IP,
		Secret:  string(open.Data),
	}
	cmf(get)
	require.NoError(t, get.Err)
	ui := new(UserInfo)
	e := json.Unmarshal(get.Data, ui)
	require.NoError(t, e)
	rui := &UserInfo{
		UserName:    open.Cred.User,
		Name:        open.Cred.User,
		Groups:      []string{"group1"},
		Quota:       "512 B",
		BytesQuota:  512,
		Consumption: "19 B",
		BytesCons:   19,
	}
	require.Equal(t, rui, ui)
}

const testConsMap = `
{
	"lastReset":"2019-09-07T00:00:00Z",
	"consumptions":{"user0":512,"user1":256}
}`
