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
)

type Cmd struct {
	Cmd       string           `json:"cmd"`
	User      string           `json:"user"`
	Manager   string           `json:"manager"`
	Secret    string           `json:"secret"`
	IsAdmin   bool             `json:"isAdmin"`
	Cred      *Credentials     `json:"cred"`
	String    string           `json:"string"`
	Uint64    uint64           `json:"uint64"`
	Groups    []string         `json:"groups"`
	Ok        bool             `json:"ok"`
	IP        string           `json:"ip"`
	Data      []byte           `json:"data"`
	Err       error            `json:"-"`
	Operation *proxy.Operation `json:"-"`
	Result    *proxy.Result    `json:"-"`

	interp  map[string]*MatchType
	consR   []string
	defKeys []string
}

type Credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type ObjType struct {
	Object map[string]interface{} `json:"object"`
	Type   string                 `json:"type"`
}

type MatchType struct {
	Match bool   `json:"match"`
	Type  string `json:"type"`
}

type DiscoverRes struct {
	MatchMng map[string]*MatchType `json:"matchMng"`
	Result   string                `json:"result"`
}

func (c *Cmd) defined(key string) (ok bool) {
	ib := func(i int) bool { return c.defKeys[i] == key }
	ok, _ = alg.BLnSrch(ib, len(c.defKeys))
	return
}

type CmdF func(*Cmd) bool

const (
	Skip       = "skip"
	Get        = "get"
	Set        = "set"
	HandleConn = "handleConn"
	Show       = "show"
	Match      = "match"
	Encrypt    = "encrypt"
	Decrypt    = "decrypt"
)
