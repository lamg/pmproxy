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
	"encoding/json"
	"fmt"
	"github.com/c2h5oh/datasize"
	"github.com/lamg/proxy"
	"github.com/pelletier/go-toml"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	ht "net/http/httptest"
	"testing"
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
	require.Equal(t, "1 KB", c.DwnConsR.GroupQuota["group0"])
	fs := afero.NewMemMapFs()
	consMap := `{
	"lastReset":"2011-01-01T00:00:00Z",
	"consumptions":{"user0":512,"user1":256}
}`
	afero.WriteFile(fs, "/down.json", []byte(consMap), 0644)
	e = c.DwnConsR.init(fs, "/")
	require.NoError(t, e)
	q := c.DwnConsR.quota("user0", []string{"group0"})
	require.Equal(t, uint64(datasize.KB), q)
	cons := c.DwnConsR.consumption("user0")
	require.Equal(t, uint64(512), cons)
}

func TestDwnConsRHandleConn(t *testing.T) {
	_, ctl, _ := openTest(t)
	res := ctl(&proxy.Operation{
		Command: proxy.Open,
		IP:      ht.DefaultRemoteAddr,
	})
	require.NoError(t, res.Error)
	res = ctl(&proxy.Operation{
		Command: proxy.ReadRequest,
		IP:      ht.DefaultRemoteAddr,
		Amount:  1024,
	})
	require.NoError(t, res.Error)
	res = ctl(&proxy.Operation{
		Command: proxy.ReadReport,
		IP:      ht.DefaultRemoteAddr,
		Amount:  1024,
	})
	require.NoError(t, res.Error)
	res = ctl(&proxy.Operation{
		Command: proxy.ReadRequest,
		IP:      ht.DefaultRemoteAddr,
		Amount:  1,
	})
	require.Equal(t,
		fmt.Errorf("Consumption reached quota %s", "1024 B"),
		res.Error)
}

func TestDwnConsRGet(t *testing.T) {
	cmf, _, _ := openTest(t)
	get := &Cmd{
		Manager: "down",
		Cmd:     Get,
		IP:      ht.DefaultRemoteAddr,
	}
	cmf(get)
	require.NoError(t, get.Err)
	ui := new(UserInfo)
	e := json.Unmarshal(get.Data, ui)
	require.NoError(t, e)
	rui := &UserInfo{
		UserName:    "user0",
		Groups:      []string{"group0"},
		Quota:       "1024 B",
		BytesQuota:  1024,
		BytesCons:   0,
		Consumption: "0 B",
	}
	require.Equal(t, rui, ui)
}

func TestDwnConsRSet(t *testing.T) {
	cmf, _, _ := openTest(t)
	set := &Cmd{
		Manager: "down",
		Cmd:     Set,
		String:  "user1",
		Uint64:  19,
		IP:      ht.DefaultRemoteAddr,
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
	}
	cmf(get)
	require.NoError(t, get.Err)
	ui := new(UserInfo)
	e := json.Unmarshal(get.Data, ui)
	require.NoError(t, e)
	rui := &UserInfo{
		UserName:    open.Cred.User,
		Groups:      []string{"group1"},
		Quota:       "512 B",
		BytesQuota:  512,
		Consumption: "19 B",
		BytesCons:   19,
	}
	require.Equal(t, rui, ui)
}
