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

func (g *globAdm) exec(c *AdmCmd) (r []byte, e error) {
	adm, _ := g.conf.checkAdmin(cmd.Secret)
	cmd.IsAdmin = adm != ""
	v, ok := c.admins.Load(c.Manager)
	if ok {
		r, e = (v.(admin))(cmd)
	} else if c.Manager == "global" {
		var mng *manager
		switch c.Cmd {
		case "add-bwCons":
			bw := newBwCons(cmd.MngName, cmd.FillInterval,
				cmd.Capacity)
			g.adms.Store(bw.Name, bw.admin)
			g.cons.Store(bw.Name, bw.consR())
			g.toSer.Store(bw.Name, bw.toSer)
		case "add-connCons":
			cn := newConnCons(cmd.MngName, cmd.Limit)
			g.adms.Store(cn.Name, cn.admin)
			g.cons.Store(cn.Name, cn.consR())
			g.toSer.Store(cn.Name, cn.toSer)
		case "add-dwCons":
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
		case "add-trCons":
			tr := &trCons{
				Name:  c.Name,
				Span:  c.Span,
				clock: g.clock,
			}
			g.adms.Store(tr.Name, tr.admin)
			g.consR.Store(tr.Name, tr.consR())
			g.toSer.Store(tr.Name, tr.toSer)
		case "add-groupIPM":
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
		case "add-rangeIPM":
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
		case "add-sessionIPM":
			sm := newSessionIPM(c.Name,
				func() []string { return g.conf.admins },
				func() *crypt { return g.conf.crypt },
				func(s string) (u *userDB) {
					v, ok := g.usrDBs.Load(s)
					if ok {
						u = v.(*userDB)
					} else {
						// TODO
					}
					return
				},
			)
			g.adms.Store(sm.Name, sm.admin)
			g.ipms.Store(sm.Name, sm.match)
			g.toSer.Store(sm.Name, sm.toSer)
		case "add-userIPM":
			um := &userIPM{
				Name:   c.Name,
				IPUser: c.IPUser,
				iu: func(s string) (iu ipUser) {
					v, ok := g.ipUI.Load(s)
					if ok {
						iu = v.(*ipUserInf).ipUser
					} else {
						// TODO
					}
				},
			}
			g.adms.Store(um.Name, um.admin)
			g.ipms.Store(um.Name, um.match)
			g.toSer.Store(um.Name.um.toSer)
		case "add-userDB":
			// TODO
		case "del-manager":
		default:
			e = NoCmd(c.Cmd)
		}
		if mng != nil {
			g.mngs.Store(mng.Name, mng)
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
