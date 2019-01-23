package pmproxy

import (
	"github.com/lamg/clock"
	rt "github.com/lamg/rtimespan"
	"os"
	"sync"
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

type admin func(*AdmCmd) ([]byte, error)

type ipQuota func(ip) uint64

type ipGroup func(ip) ([]string, error)
type ipUserInf struct {
	ipg ipGroup
	ipu ipUser
}

func newGlobAdm() (g *globAdm, e error) {
	viper.SetConfigName("conf")
	viper.AddConfigPath("/etc/pmproxy")
	viper.AddConfigPath("$HOME/.config/pmproxy")
	e = viper.ReadInConfig()

	g.adms.Store(configT, g.conf.admin)
	g.toSer.Store(configT, g.conf.toSer)
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
			"lastReset":  "2019-01-19 00:00:00-05:00",
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
	Limit        uint64        `json: "limit"`
	UserDB       *userDB       `json: "usrDB"`
	DialTimeout  time.Duration `json: "dialTimeout"`
	Date         time.Time     `json: "date"`
	Span         *rt.RSpan     `json: "span"`
	Group        string        `json: "group"`
	IsAdmin      bool          `json: "isAdmin"`
	CIDR         string        `json: "cidr"`
}

const (
	globAdmN      = "globar"
	addBwCons     = "addBwCons"
	addConnCons   = "addConnCons"
	addDwCons     = "addDwCons"
	addTrCons     = "addTrCons"
	addGroupIPM   = "addGroupIPM"
	addRangeIPM   = "addRangeIPM"
	addSessionIPM = "addSessionIPM"
	addUserIPM    = "addUserIPM"
	addUserDB     = "addUserDB"
	delManager    = "delManager"
)

func (g *globAdm) exec(c *AdmCmd) (r []byte, e error) {
	adm, _ := g.conf.checkAdmin(cmd.Secret)
	cmd.IsAdmin = adm != ""
	v, ok := c.admins.Load(c.Manager)
	if ok {
		r, e = (v.(admin))(cmd)
	} else if c.Manager == globAdmN {
		var mng *manager
		switch c.Cmd {
		case addBwCons:
			bw := newBwCons(cmd.MngName, cmd.FillInterval,
				cmd.Capacity)
			g.adms.Store(bw.Name, bw.admin)
			g.cons.Store(bw.Name, bw.consR())
			g.toSer.Store(bw.Name, bw.toSer)
		case addConnCons:
			cn := newConnCons(cmd.MngName, cmd.Limit)
			g.adms.Store(cn.Name, cn.admin)
			g.cons.Store(cn.Name, cn.consR())
			g.toSer.Store(cn.Name, cn.toSer)
		case addDwCons:
			dw := &dwnCons{
				Name:       c.MngName,
				IPUser:     c.IPUser,
				IPQuota:    c.IPQuota,
				LastReset:  c.Date,
				ResetCycle: c.FillInterval,
				iu: func(name string) (i ipUser) {
					v, ok := g.ipUInf.Load(name)
					if ok {
						i = v.(*ipUserInf).ipUser
					} else {
						i = func(n ip) (s string) { return }
					}
					return
				},
				gq: func(name string) (i ipQuota) {
					v, ok := g.ipQs.Load(name)
					if ok {
						i = v.(ipQuota)
					} else {
						i = func(n ip) (q uint64) { return }
					}
					return
				},
				usrCons: new(sync.Map),
			}
			g.adms.Store(dw.Name, dw.admin)
			g.cons.Store(dw.Name, dw.consR())
			g.toSer.Store(dw.Name, dw.toSer)
		case addTrCons:
			tr := &trCons{
				Name:  c.Name,
				Span:  c.Span,
				clock: g.clock,
			}
			g.adms.Store(tr.Name, tr.admin)
			g.consR.Store(tr.Name, tr.consR())
			g.toSer.Store(tr.Name, tr.toSer)
		case addGroupIPM:
			gp := &groupIPM{
				Name:  c.Name,
				Group: c.Group,
				IPGrp: c.IPUser,
				ipGs: func(name string) (i ipGroup) {
					v, ok := g.ipUI.Load(name)
					if ok {
						i = v.(*ipUserInf).ipGroup
					} else {
						i = func(n ip) (gs []string, e error) { return }
					}
					return
				},
			}
			g.adms.Store(gp.Name, gp.admin)
			g.ipms.Store(gp.Name, gp.match)
			g.toSer.Store(gp.Name, gp.toSer)
		case addRangeIPM:
			rm := &rangeIPM{
				CIDR: c.CIDR,
				Name: c.Name,
			}
			e = m.init()
			if e == nil {
				g.adms.Store(rm.Name, rm.admin)
				g.ipms.Store(rm.Name, rm.match)
				g.toSer.Store(rm.Name, rm.toSer)
			}
		case addSessionIPM:
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
				usrGroupN: func(name string) (g usrGrp) {
					v, ok := g.usrDBs.Load(name)
					if ok {
						a = v.(*userDB).grps
					} else {
						a = func(u string) (gs []string, e error) {
							e = fmt.Errorf("Zero userGrp")
							return
						}
					}
				},
				admins:   func() []string { return g.conf.admins },
				crypt:    func() *crypt { return g.conf.crypt },
				sessions: new(sync.Map),
				grpCache: new(sync.Map),
			}
			g.adms.Store(sm.Name, sm.admin)
			g.ipms.Store(sm.Name, sm.match)
			g.toSer.Store(sm.Name, sm.toSer)
		case addUserIPM:
			um := &userIPM{
				Name:   c.Name,
				IPUser: c.IPUser,
				iu: func(s string) (iu ipUser) {
					v, ok := g.ipUI.Load(s)
					if ok {
						iu = v.(*ipUserInf).ipUser
					} else {
						iu = func(i ip) (u string) { return }
					}
				},
			}
			g.adms.Store(um.Name, um.admin)
			g.ipms.Store(um.Name, um.match)
			g.toSer.Store(um.Name, um.toSer)
		case addUserDB:
			udb := c.UserDB
			if udb.SrcType == adSrc {
				e = u.initAD()
			} else if udb.SrcType == mapSrc {
				e = u.initMap()
			} else {
				e = fmt.Errorf("Unrecognized type %s", udb.Type)
			}
			if e == nil {
				g.usrDBs.Store(udb.Name, udb)
			}
		case delManager:
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
		default:
			e = NoCmd(c.Cmd)
		}
	} else {
		e = NoMngWithName(c.Manager)
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
	os.Rename(g.conf.file, g.conf.file+".back")
	viper.WriteConfigAs(g.conf.file)
	return
}

func NoKey(k string) (e error) {
	e = fmt.Errorf("No key %s", c.Group)
	return
}
