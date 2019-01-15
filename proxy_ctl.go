package pmproxy

import (
	"github.com/spf13/viper"
	"io"
	"net"
	h "net/http"
	"time"
)

// ProxyCtl has the handlers for the HTTP servers
type ProxyCtl struct {
	// contains the fields for initializing
	// github.com/lamg/proxy.Proxy
	PrxFls  *SpecCtx
	adm     *globalAdm
	Persist func(io.Writer) error
}

type defConf func() *config

func NewProxyCtl(dc defConf) (p *ProxyCtl, e error) {
	viper.SetConfigName("conf")
	viper.AddConfigPath("/etc/pmproxy")
	viper.AddConfigPath("$HOME/.config/pmproxy")
	p.Persist = p.adm.persist
	e = viper.ReadInConfig()
	var c *config
	if e != nil {
		c, e = dc(), nil
	} else {
		c = new(config)
		c.ad, e = readAD()
	}
	if e == nil {
		c.admins, e = readAdms()
	}
	if e == nil {
		c.bwcs, e = readBwCons()
	}
	if e == nil {
		c.cncs, e = readConnCons()
	}
	if e == nil {
		c.dialTimeout, e = readTimeout()
	}
	if e == nil {
		c.dwcs, e = readDwnCons()
	}
	if e == nil {
		c.gms, e = readGroupM()
	}
	if e == nil {
		c.IdR = new(idCons)
		c.NegR = new(negCons)
		c.lg, e = readLogger()
	}
	if e == nil {
		c.rms, e = readRangeIPM()
	}
	if e == nil {
		c.rspec, e = readRspec()
	}
	if e == nil {
		c.sms, e = readSessionIPM()
	}
	if e == nil {
		c.ums, e = readUserIPM()
	}
	if e == nil {
		c.crypt, e = newCrypt()
	}
	if e == nil {
		c.clock = new(clock.OSClock)
	}
	return
}

func setDefaults(adm string) (c *config) {
	c = &config{
		Admins: []string{adm},
	}
	viper.SetDefault("rule", []map[string]interface{}{
		{
			"unit": true,
			"pos":  0,
			"ipm":  "sm",
			"spec": map[string]interface{}{
				"iface": "eth0",
				"consR": []string{"dw", "cn", "bw"},
			},
		},
	})
	viper.SetDefault("bwCons", []map[string]interface{}{
		{
			"name":     "bw",
			"capacity": 100,
			"duration": time.Second.String(),
		},
	})
	viper.SetDefault("connCons", []map[string]interface{}{
		{
			"name":  "cn",
			"limit": 100,
		},
	})
	viper.SetDefault("dwCons", []map[string]interface{}{
		{
			"name":       "dw",
			"ipUser":     "sm",
			"userQt":     "qt",
			"lastReset":  "2019-01-12 00:00:00-05:00",
			"resetCycle": "168h",
		},
	})
	viper.SetDefault("dialTimeout", "30s")
	viper.SetDefault("sessionIPM", []map[string]interface{}{
		{
			"name": "sm",
			"auth": "ad",
		},
	})
	viper.SetDefault("userDB", []map[string]interface{}{
		{
			"name": "ad",
			"type": "AD",
			"addr": "ad.upr.edu.cu:636",
			"bdn":  "dc=upr,dc=edu,dc=cu",
			"suff": "@upr.edu.cu",
			"user": "xyz",
			"pass": "abc",
		},
	})
	return
}

// ServeHTTP is the handler that implements the
// administration interface to be served by an HTTP server
func (p *ProxyCtl) ServeHTTP(w h.ResponseWriter,
	r *h.Request) {
	ips, _, e := net.SplitHostPort(r.RemoteAddr)
	var cmd *AdmCmd
	if e == nil {
		cmd = new(AdmCmd)
		e = Decode(r.Body, cmd)
	}
	var bs []byte
	if e == nil {
		r.Body.Close()
		cmd.RemoteIP = ips
		bs, e = p.adm.exec(cmd)
	}
	if e == nil {
		_, e = w.Write(bs)
	}
	if e != nil {
		h.Error(w, e.Error(), h.StatusBadRequest)
	}
}

func (p *ProxyCtl) Persist(w io.Writer) (e error) {
	e = p.adm.persist(w)
	return
}
