package pmproxy

import (
	"github.com/spf13/cast"
	"github.com/spf13/viper"
	"sync"
)

type conf struct {
	iu       *ipUser
	admins   *sync.Map
	matchers *sync.Map
}

func newConf(iu *ipUser) (c *conf) {
	c = &conf{
		iu:     iu,
		admins: *sync.Map,
	}
	viper.SetConfigName("conf")
	viper.AddConfigPath("/etc/pmproxy")
	viper.AddConfigPath("$HOME/.config/pmproxy")
	viper.ReadInConfig()
	return
}

func (c *conf) get(key string) (v interface{}) {
	v = viper.Get(key)
	return
}

func (c *conf) sliceE(key string) (sl []interface{},
	e error) {
	sl, e = cast.ToSliceE(c.get(key))
	return
}

func (c *conf) böol(key string) (b bool) {
	b = viper.GetBool(key)
	return
}

func (c *conf) strïng(key string) (s string) {
	s = viper.GetString(key)
	return
}

func (c *conf) configPath(file string) (fpath string) {
	cfl := viper.ConfigFileUsed()
	fpath = path.Join(path.Dir(cfl), file)
	return
}

func (c *conf) sessionIPMs() (e error) {
	sms := make([]*sessionIPM, 0)
	fm := func(i interface{}) {
		sm := new(sessionIPM)
		e = sm.fromMap(i)
		if e == nil {
			sms = append(sms, sm)
		}
	}
	e = sliceMap("sessionIPM", fm,
		func() bool { return e == nil })
	return
}

func (c *conf) dwnConsRs() (e error) {
	dws := make([]*dwnConsR, 0)
	fm := func(i interface{}) {
		dw := new(dwnConsR)
		e = dw.fromMap(i)
		if e == nil {
			dws = append(dws, dw)
		}
	}
	e = sliceMap("dwnConsR", fm,
		func() bool { return e == nil })
	return
}

func (c *conf) sliceMap(key string, fm func(interface{}),
	bf func() bool) (e error) {
	vs, e := c.sliceE(key)
	if e == nil {
		inf := func(i int) (b bool) {
			fm(vs[i])
			b = bf()
			return
		}
		trueForall(inf, len(vs))
	}
	return
}

func (c *conf) userInfo() (ui *userInfo, e error) {
	ui = &userInfo{
		iu:       c.iu,
		userName: c.udb.userName,
		quota:    c.quotas.get,
		userIsAdm: func(user string) (v bool) {
			v, _ = bLnSrch(func(i int) bool {
				return c.admins[i] == user
			},
				len(c.admins),
			)
		},
	}
	return
}

func (c *conf) admin(cmd *admCmd) (bs []byte, e error) {
	if cmd.Cmd != skip {
		v, ok := c.admins.Load(cmd.Adm)
		if ok {
			bs, e = (v.(admin))(cmd)
		}
	}
	return
}
