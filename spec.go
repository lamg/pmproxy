package pmproxy

import (
	"net/url"
)

type spec struct {
	Iface    string   `json:"iface"`
	ProxyURL string   `json:"proxyURL"`
	ConsR    []string `json:"consR"`

	proxyURL *url.URL
}

func (s *spec) init() (e error) {
	s.proxyURL, e = url.Parse(s.ProxyURL)
	return
}
