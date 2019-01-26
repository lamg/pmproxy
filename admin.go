package pmproxy

import (
	"fmt"
	"github.com/lamg/clock"
	rt "github.com/lamg/rtimespan"
	"github.com/spf13/viper"
	"io"
	"os"
	"sync"
	"time"
)

type globAdm struct {
	adms   *sync.Map // admins
	cons   *sync.Map // consRs
	ipms   *sync.Map // ipMatchers
	ipUI   *sync.Map // ipUserInfs
	ipQs   *sync.Map // ipQuotas
	usrDBs *sync.Map // userDBs
	toSer  *sync.Map // toSers
	conf   *config
	clock  clock.Clock
}

type toSer func() (string, interface{})

type admin func(*AdmCmd, fbs, ferr) []cmdProp

type ipQuota func(string) uint64

type ipGroup func(string) ([]string, error)
type ipUser func(string) string

type ipUserInf struct {
	ipg ipGroup
	ipu ipUser
}

func newGlobAdm() (g *globAdm, e error) {
	viper.SetConfigName("conf")
	viper.AddConfigPath("/etc/pmproxy")
	viper.AddConfigPath("$HOME/.config/pmproxy")
	e = viper.ReadInConfig()

	// TODO
	g.adms.Store(configT, g.conf.admin)
	g.adms.Store(globAdmN, g.admin)
	g.toSer.Store(configT, g.conf.toSer)
	return
}

func setDefaults(adm string) (c *config) {
	c = &config{
		admins: []string{adm},
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
	viper.SetDefault(bwConsT, []map[string]interface{}{
		{
			"name":     "bw",
			"capacity": 100,
			"duration": time.Second.String(),
		},
	})
	viper.SetDefault(connConsT, []map[string]interface{}{
		{
			"name":  "cn",
			"limit": 100,
		},
	})
	viper.SetDefault(dwnConsT, []map[string]interface{}{
		{
			"name":       "dw",
			"ipUser":     "sm",
			"userQt":     "qt",
			"lastReset":  "2019-01-19 00:00:00-05:00",
			"resetCycle": "168h",
		},
	})
	viper.SetDefault("dialTimeout", "30s")
	viper.SetDefault(sessionIPMT, []map[string]interface{}{
		{
			"name": "sm",
			"auth": "ad",
		},
	})
	viper.SetDefault(userDBT, []map[string]interface{}{
		{
			nameK: "ad",
			srcK:  adSrc,
			paramsK: map[string]string{
				addrK: "ad.upr.edu.cu:636",
				bdnK:  "dc=upr,dc=edu,dc=cu",
				suffK: "@upr.edu.cu",
				userK: "xyz",
				passK: "abc",
			},
		},
		{
			nameK: "map",
			srcK:  mapSrc,
			paramsK: map[string]string{
				"coco": "pepe",
			},
		},
	})
	return
}

// AdmCmd is an administration command
type AdmCmd struct {
	Manager      string        `json: "mng"`
	Cmd          string        `json: "cmd"`
	User         string        `json: "user"`
	Pass         string        `json: "pass"`
	Pos          []int         `json: "pos"`
	Rule         *rule         `json: "rule"`
	Secret       string        `json: "secr"`
	RemoteIP     string        `json: "remoteIP"`
	MngName      string        `json: "mngName"`
	MngType      string        `json: "mngType"`
	Capacity     int64         `json: "capacity"`
	FillInterval time.Duration `json: "fillInterval"`
	IPUser       string        `json: "ipUser"`
	IPQuota      string        `json: "ipQuota"`
	Limit        uint32        `json: "limit"`
	UserDB       *userDB       `json: "usrDB"`
	DialTimeout  time.Duration `json: "dialTimeout"`
	Date         time.Time     `json: "date"`
	Span         *rt.RSpan     `json: "span"`
	Group        string        `json: "group"`
	IsAdmin      bool          `json: "isAdmin"`
	CIDR         string        `json: "cidr"`
	Prop         string        `json: "prop"`
}

const (
	globAdmN    = "global"
	add         = "add"
	open        = "open"
	clöse       = "close"
	show        = "show"
	get         = "get"
	set         = "set"
	del         = "del"
	prop        = "prop"
	reset       = "reset"
	all         = "all"
	nameK       = "name"
	ipUserK     = "ipUser"
	ipQuotaK    = "ipQuota"
	lastResetK  = "lastReset"
	resetCycleK = "resetCycle"
	userQtK     = "userQt"
)

func (g *globAdm) dispatch(c *AdmCmd) (r []byte, e error) {
	adm, _ := g.conf.checkAdmin(c.Secret)
	c.IsAdmin = adm != ""
	v, ok := g.adms.Load(c.Manager)
	if ok {
		fe := func(d error) { e = d }
		cs := (v.(admin))(c, func(b []byte) { r = b }, fe)
		exCmdProp(cs, c, fe)
	} else {
		e = NoMngWithName(c.Manager)
	}
	return
}

func (g *globAdm) admin(c *AdmCmd, fb fbs,
	fe ferr) (cs []cmdProp) {
	cs = []cmdProp{
		{
			cmd:  add,
			prop: bwConsT,
			f: func() {
				bw := newBwCons(c.MngName, c.FillInterval,
					c.Capacity)
				g.adms.Store(bw.Name, bw.admin)
				g.cons.Store(bw.Name, bw.consR())
				g.toSer.Store(bw.Name, bw.toSer)
			},
		},
		{
			cmd:  add,
			prop: connConsT,
			f: func() {
				cn := newConnCons(c.MngName, c.Limit)
				g.adms.Store(cn.Name, cn.admin)
				g.cons.Store(cn.Name, cn.consR())
				g.toSer.Store(cn.Name, cn.toSer)
			},
		},
		{
			cmd:  add,
			prop: dwnConsT,
			f: func() {
				dw := &dwnCons{
					Name:       c.MngName,
					IPUser:     c.IPUser,
					IPQuota:    c.IPQuota,
					LastReset:  c.Date,
					ResetCycle: c.FillInterval,
					iu: func(name string) (i ipUser) {
						v, ok := g.ipUI.Load(name)
						if ok {
							i = v.(*ipUserInf).ipu
						} else {
							i = func(ip string) (s string) { return }
						}
						return
					},
					gq: func(name string) (i ipQuota) {
						v, ok := g.ipQs.Load(name)
						if ok {
							i = v.(ipQuota)
						} else {
							i = func(ip string) (q uint64) { return }
						}
						return
					},
					usrCons: new(sync.Map),
				}
				g.adms.Store(dw.Name, dw.admin)
				g.cons.Store(dw.Name, dw.consR())
				g.toSer.Store(dw.Name, dw.toSer)
			},
		},
		{
			cmd:  add,
			prop: trConsT,
			f: func() {
				tr := &trCons{
					Name:  c.MngName,
					Span:  c.Span,
					clock: g.clock,
				}
				g.adms.Store(tr.Name, tr.admin)
				g.cons.Store(tr.Name, tr.consR())
				g.toSer.Store(tr.Name, tr.toSer)
			},
		},
		{
			cmd:  add,
			prop: groupIPMT,
			f: func() {
				gp := &groupIPM{
					Name:  c.MngName,
					Group: c.Group,
					IPGrp: c.IPUser,
					ipGS: func(name string) (i ipGroup) {
						v, ok := g.ipUI.Load(name)
						if ok {
							i = v.(*ipUserInf).ipg
						} else {
							i = func(ip string) (gs []string,
								e error) {
								return
							}
						}
						return
					},
				}
				g.adms.Store(gp.Name, gp.admin)
				g.ipms.Store(gp.Name, gp.match)
				g.toSer.Store(gp.Name, gp.toSer)
			},
		},
		{
			cmd:  add,
			prop: rangeIPMT,
			f: func() {
				rm := &rangeIPM{
					CIDR: c.CIDR,
					Name: c.MngName,
				}
				e := rm.init()
				if e == nil {
					g.adms.Store(rm.Name, rm.admin)
					g.ipms.Store(rm.Name, rm.match)
					g.toSer.Store(rm.Name, rm.toSer)
				}
			},
		},
		{
			cmd:  add,
			prop: sessionIPMT,
			f: func() {
				sm := &sessionIPM{
					Name:   c.MngName,
					UserDB: c.UserDB.Name,
					authNormN: func(name string) (a authNorm) {
						v, ok := g.usrDBs.Load(name)
						if ok {
							a = v.(*userDB).auth
						} else {
							a = func(u, p string) (r string, e error) {
								e = fmt.Errorf("Zero authNorm")
								return
							}
						}
						return
					},
					usrGroupN: func(name string) (a userGrp) {
						v, ok := g.usrDBs.Load(name)
						if ok {
							a = v.(*userDB).grps
						} else {
							a = func(u string) (gs []string, e error) {
								e = fmt.Errorf("Zero userGrp")
								return
							}
						}
						return
					},
					admins: func() []string {
						return g.conf.admins
					},
					crypt:    func() *crypt { return g.conf.crypt },
					sessions: new(sync.Map),
					grpCache: new(sync.Map),
				}
				g.adms.Store(sm.Name, sm.admin)
				g.ipms.Store(sm.Name, sm.match)
				g.toSer.Store(sm.Name, sm.toSer)
			},
		},
		{
			cmd:  add,
			prop: userIPMT,
			f: func() {
				um := &userIPM{
					Name:   c.MngName,
					IPUser: c.IPUser,
					iu: func(s string) (iu ipUser) {
						v, ok := g.ipUI.Load(s)
						if ok {
							iu = v.(*ipUserInf).ipu
						} else {
							iu = func(ip string) (u string) { return }
						}
						return
					},
				}
				g.adms.Store(um.Name, um.admin)
				g.ipms.Store(um.Name, um.match)
				g.toSer.Store(um.Name, um.toSer)
			},
		},
		{
			cmd:  add,
			prop: userDBT,
			f: func() {
				udb := c.UserDB
				var e error
				var kf []kFuncI
				fe := func(d error) { e = d }
				if udb.SrcType == adSrc {
					kf = udb.fromMapKFLd(fe)
				} else if udb.SrcType == mapSrc {
					kf = udb.fromMapKFMp(fe)
				} else {
					e = fmt.Errorf("Unrecognized type %s",
						udb.SrcType)
				}
				mapKF(kf, udb.Params, fe,
					func() (b bool) {
						e = udb.errFunc(e)
						b = e != nil
						return
					},
				)
				if e == nil {
					g.usrDBs.Store(udb.Name, udb)
				}
			},
		},
		{
			cmd:  add,
			prop: groupQuotaT,
			f: func() {
				// TODO
			},
		},
		{
			cmd:  del,
			prop: all,
			f: func() {
				fs := []*sync.Map{
					g.adms,
					g.cons,
					g.ipQs,
					g.ipUI,
					g.ipms,
					g.toSer,
					g.usrDBs,
				}
				forall(func(i int) { fs[i].Delete(c.MngName) },
					len(fs))
			},
		},
	}
	return
}

func (g *globAdm) persist(w io.Writer) (e error) {
	sm := make(map[string][]interface{})
	// for TOML array of tables
	g.toSer.Range(func(k, v interface{}) (ok bool) {
		ks, vm := k.(string), v.(toSer)
		tỹpe, mp := vm()
		if ks == tỹpe {
			viper.Set(ks, mp)
		} else {
			// vm is part of an array of tables
			sm[tỹpe] = append(sm[tỹpe], mp)
		}
		return
	})
	for k, v := range sm {
		viper.Set(k, v)
	}
	fl := viper.ConfigFileUsed()
	os.Rename(fl, fl+".back")
	viper.WriteConfigAs(fl)
	return
}

func NoKey(k string) (e error) {
	e = fmt.Errorf("No key %s", k)
	return
}
