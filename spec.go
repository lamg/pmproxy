package pmproxy

import (
	"net/url"
)

const (
	ifaceK    = "iface"
	consRK    = "consR"
	proxyURLK = "proxyURL"
)

type spec struct {
	Iface    string `json:"iface"`
	ProxyURL string `json:"proxyURL"`
	proxyURL *url.URL
	ConsR    []string `json:"consR"`
}

func (s *spec) init() (e error) {
	s.proxyURL, e = url.Parse(s.ProxyURL)
	return
}

func (s *spec) toSer() (m map[string]interface{}) {
	m = map[string]interface{}{
		ifaceK:    s.Iface,
		proxyURLK: s.ProxyURL,
		consRK:    s.ConsR,
	}
	return
}

func (s *spec) fromMapKF(fe ferr) (kf []kFuncI) {
	kf = []kFuncI{
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
			consRK,
			func(i interface{}) {
				s.ConsR = stringSliceE(i, fe)
			},
		},
	}
	return
}
