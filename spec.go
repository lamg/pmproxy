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
	"fmt"
	pred "github.com/lamg/predicate"
	"net/url"
)

type spec struct {
	Iface    string `json:"iface"`
	ProxyURL string `json:"proxyURL"`
	proxyURL *url.URL
	ConsRs   []string        `json:"consRs"`
	Result   *pred.Predicate `json:"result"`
	ip       string
	user     string
}

func (s *spec) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	mp := stringMapE(i, fe)
	if e == nil {
		vp, vi, vc := mp[proxyURLK], mp[ifaceK], mp[consRK]
		if vp != nil {
			s.ProxyURL = vp.(string)
		}
		if vi != nil {
			s.Iface = vi.(string)
		}
		if s.ProxyURL != "" {
			fe(s.init())
		}
		if vc != nil {
			s.ConsRs = vc.([]string)
		}
	}
	if e == nil && s.Iface == "" {
		e = fmt.Errorf("spec without interface")
	}
	return
}

func (s *spec) toMap() (i map[string]interface{}) {
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

func join(s, t *spec, consR string) {
	// the policy consists in replacing when empty
	if s.ProxyURL == "" {
		s.ProxyURL = t.ProxyURL
		s.proxyURL = t.proxyURL
	}
	if s.Iface == "" {
		s.Iface = t.Iface
	}
	s.ConsRs = append(s.ConsRs, consR)
	return
}
