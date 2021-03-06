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
	"fmt"
	"net/url"

	"github.com/lamg/proxy"
)

type Cmd struct {
	Cmd     string       `json:"cmd"`
	Manager string       `json:"manager"`
	Secret  string       `json:"secret"`
	Cred    *Credentials `json:"cred"`
	Info    *UserInfo    `json:"info"`

	ok          bool
	isAdmin     bool
	data        []byte
	ip          string
	err         error
	rqp         *proxy.ReqParams
	parentProxy *url.URL
	iface       string
	interp      map[string]*MatchType
	consR       []string
	internal    bool
	loggedBy    *userAuth
	result      string
}

type UserInfo struct {
	Quota       string   `json:"quota"`
	Groups      []string `json:"groups"`
	Name        string   `json:"name"`
	UserName    string   `json:"userName"`
	Consumption string   `json:"consumption"`
	BytesQuota  uint64   `json:"bytesQuota"`
	BytesCons   uint64   `json:"bytesCons"`
	IsAdmin     bool     `json:"isAdmin"`
}

type Credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type MatchType struct {
	Match bool   `json:"match"`
	Type  string `json:"type"`
}

type DiscoverRes struct {
	MatchMng map[string]*MatchType `json:"matchMng"`
	Result   string                `json:"result"`
}

type CmdF func(*Cmd, string) ([]byte, error)

const (
	Open        = "open"
	Close       = "close"
	Auth        = "authenticate"
	Check       = "check"
	Skip        = "skip"
	Get         = "get"
	Set         = "set"
	readRequest = "readRequest"
	readReport  = "readReport"
	Show        = "show"
	Match       = "match"
	Encrypt     = "encrypt"
	Decrypt     = "decrypt"
	Discover    = "discover"
	Filter      = "filter"
	GetOther    = "getOther"
	isAdmin     = "isAdmin"
	encrypt     = "encrypt"
	decrypt     = "decrypt"
	Renew       = "renew"
	Protect     = "protect"

	DwnConsRK    = "dwnConsR"
	SessionIPMK  = "sessionIPM"
	IfaceK       = "iface"
	ParentProxyK = "parentProxy"
	SpanK        = "timeSpan"
	BwConsRK     = "bwConsR"
	RangeIPMK    = "rangeIPM"
	GroupIPMK    = "groupIPM"
	HostMatcher  = "hostMatcher"

	RulesK         = "rules"
	connectionsMng = "connections"
	ipUserMng      = "ipUserMng"
	adminsMng      = "adminsMng"
	cryptMng       = "crypt"

	tcp = "tcp"
)

type StringErr struct {
	Message string `json:"message"`
}

func (s *StringErr) Error() (r string) {
	r = s.Message
	return
}

func (s *StringErr) Is(e error) (ok bool) {
	ok = e != nil && s.Message == e.Error()
	return
}

type CheckErr struct {
	Logged    string
	Decrypted string
}

func (c *CheckErr) Error() (s string) {
	s = fmt.Sprintf("Check failed: '%s' ≠ '%s'", c.Logged,
		c.Decrypted)
	return
}

type ManagerErr struct {
	Mng string
	Cmd string
}

func (m *ManagerErr) Error() (s string) {
	s = fmt.Sprintf("manager not found: '%s' with command '%s'",
		m.Mng, m.Cmd)
	return
}

type NoConnErr struct {
	IP string
}

func (c *NoConnErr) Error() (s string) {
	s = fmt.Sprintf("No connection at '%s'", c.IP)
	return
}

type NoUser struct {
	User string
	DB   string
}

func (u *NoUser) Error() (s string) {
	s = fmt.Sprintf("No user '%s' at DB '%s'", u.User, u.DB)
	return
}

type NoAdmErr struct {
	User string
}

func (a *NoAdmErr) Error() (s string) {
	s = fmt.Sprintf("User '%s' isn't administrator", a.User)
	return
}

type QuotaReachedErr struct {
	Quota string
}

func (r *QuotaReachedErr) Error() (s string) {
	s = fmt.Sprintf("Consumption reached quota %s", r.Quota)
	return
}

type ForbiddenByRulesErr struct {
	Result string
}

func (c *ForbiddenByRulesErr) Error() (s string) {
	s = fmt.Sprintf("Forbidden: rules evaluated to '%s'", c.Result)
	return
}

type DependencyErr struct {
	absent []string
	tÿpe   string
	name   string
}

func (d *DependencyErr) Error() (s string) {
	s = fmt.Sprintf(
		"%s:%s ≠ nil ∧ (all %v nil) ∨ (no matching dependency name)",
		d.name, d.tÿpe, d.absent)
	return
}
