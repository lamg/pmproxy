package pmproxy

import (
	"github.com/spf13/viper"
)

type defConf func() *config

func NewProxyCtl(dc defConf) (p *ProxyCtl, e error) {
	viper.SetConfigName("conf")
	viper.AddConfigPath("/etc/pmproxy")
	viper.AddConfigPath("$HOME/.config/pmproxy")

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
	viper.SetDefault("rules", [][]jRule{
		{
			Unit: true,
			IPM:  "sm",
			Spec: &JSPec{
				Iface: "eth0",
				ConsR: []string{"bw", "cn", "dw"},
			},
		},
	})
	viper.SetDefault("bandWidthR", []*bwCons{
		newBwCons("bw", time.Millisecond, 1*MiB),
	})
	viper.SetDefault("connAmR", []*connCons{
		{
			NameF: "cn",
			Limit: 100,
		},
	})
	viper.SetDefault("sessionM", []*sessionIPM{
		{
			NameF:  "sm",
			Admins: c.Admins,
		},
	})
	viper.SetDefault("dialTimeout", 30*time.Second)
	return
}
