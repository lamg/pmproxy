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
	pred "github.com/lamg/predicate"
	"net/url"
)

type spec struct {
	Name     string `json:"name"`
	Iface    string `json:"iface"`
	ProxyURL string `json:"proxyURL"`
	proxyURL *url.URL
	// ConsRs is a map from type to description.
	// Only a ConsR of each type is assigned, as the
	// map structure implicitly determines
	ConsRs map[string]string `json:"consRs"`
	Result *pred.Predicate   `json:"result"`
	ip     string
	user   string
}

func (s *spec) fromMap(i interface{}) (e error) {
	fe := func(d error) { e = d }
	kf := []kFuncI{
		{
			nameK,
			func(i interface{}) {
				s.Name = stringE(i, fe)
			},
		},
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
		nameK:     s.Name,
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
