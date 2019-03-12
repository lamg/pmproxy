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
	"encoding/json"
	pred "github.com/lamg/predicate"
	//rt "github.com/lamg/rtimespan"
	//"github.com/spf13/cast"
	//"net"
	"net/url"
	//"regexp"
	"time"
)

// type `rules` is an interface for matching HTTP requests
// (rules.match), for managing at runtime those rules
// (rules.managerKF), and for discovering rules available
// for a client (rules.discover). It can be serialized
// (rules.toMap) and deserialized (rules.fromMap).
type resources struct {
	rules     *pred.Predicate
	sendURL   func(string)
	sendAddr  func(string)
	sendTime  func(time.Time)
	sendUser  func(string)
	sendGroup func(string)
	receive   func() *spec
}

func (r *resources) match(ürl, rAddr string,
	t time.Time) (s *spec) {
	r.sendURL(ürl)
	r.sendAddr(rAddr)
	r.sendTime(t)
	pred.Reduce(r.rules) // TODO n :=
	s = r.receive()
	return
}

func (r *resources) discover(ip string) (s *spec) {
	// TODO discovery of matchers
	return
}

func (r *resources) managerKF(c *cmd) (kf []kFunc) {
	kf = []kFunc{
		{
			add,
			func() {
			},
		},
		{
			del,
			func() {
			},
		},
		{
			show,
			func() {
				c.bs, c.e = json.Marshal(r.rules)
			},
		},
		{
			get,
			func() {
				rs := r.discover(c.RemoteAddr)
				c.bs, c.e = json.Marshal(rs)
			},
		},
	}
	return
}

type spec struct {
	Iface    string `json:"iface"`
	ProxyURL string `json:"proxyURL"`
	proxyURL *url.URL
	// ConsRs is a map from type to description.
	// Only a ConsR of each type is assigned, as the
	// map structure implicitly determines
	ConsRs map[string]string `json:"consRs"`
	ip     string
	user   string
}

func (s *spec) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			ifaceK,
			func(i interface{}) {
				s.Iface = stringE(i, fe)
			},
		},
		{
			proxyURLK,
			func(i interface{}) {
				s.ProxyURL = stringE(i, fe)
			},
		},
		{
			proxyURLK,
			func(i interface{}) {
				fe(s.init())
			},
		},
		{
			consRK,
			func(i interface{}) {
				s.ConsRs = stringMapStringE(i, fe)
			},
		},
	}
	mapKF(kf, i, fe, func() bool { return e == nil })
	return
}

func (s *spec) toMap() (i interface{}) {
	i = map[string]interface{}{
		ifaceK:    s.Iface,
		proxyURLK: s.ProxyURL,
		consRK:    s.ConsRs,
	}
	return
}

func (s *spec) init() (e error) {
	s.proxyURL, e = url.Parse(s.ProxyURL)
	return
}

func join(s, t *spec) {
	// the policy consists in replacing when empty
	if s.ProxyURL == "" {
		s.ProxyURL = t.ProxyURL
		s.proxyURL = t.proxyURL
	}
	if s.Iface == "" {
		s.Iface = t.Iface
	}
	for k, v := range t.ConsRs {
		_, ok := s.ConsRs[k]
		if !ok {
			s.ConsRs[k] = v
		}
	}
	return
}
