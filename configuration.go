package pmproxy

import (
	"encoding/json"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/lamg/clock"
	ld "github.com/lamg/ldaputil"
	"io"
	"os"
	"regexp"
	"time"
)

type adConf struct {
	User string `json:"user" toml:"user"`
	Pass string `json:"pass" toml:"pass"`
	Addr string `json:"addr" toml:"addr"`
	Bdn  string `json:"bdn"  toml:"bdn"`
	Suff string `json:"suff" toml:"suff"`
}

type config struct {
	Rules  [][]jRule `toml: "rules"`
	Admins []string  `toml: "admins"`
	AD     *adConf   `toml: "ad"`

	// arrays of TOML representations of all IPMatcher and ConsR
	// implementations
	BandWidthR []*bwCons   `toml: "bandWidthR"`
	ConnAmR    []*connCons `toml: "connAmR"`
	DownR      []*dwnCons  `toml: "downR"`
	NegR       *negCons    `toml: "negR"`
	IdR        *idCons     `toml: "idR"`
	TimeRangeR []*trCons   `toml: "timeRangeR"`

	SessionM []*sessionIPM `toml: "sessionM"`
	GroupM   []*groupIPM   `toml: "groupM"`
	UserM    []*userIPM    `toml: "userM`
	RangeIPM []*rangeIPM   `toml: "rangeM"`

	DialTimeout *time.Duration `toml: "dialTimeout"`
	Logger      *logger        `toml:"logger"`

	crypt *Crypt
	rspec *simpleRSpec
	clock clock.Clock
}

func NewProxyCtl(rd io.Reader) (c *ProxyCtl, e error) {
	cfg := new(config)
	_, e = toml.DecodeReader(rd, cfg)
	if e == nil {
		cfg.clock = new(clock.OSClock)
		bf := func(i int) {
			cfg.BandWidthR[i].init()
		}
		forall(bf, len(cfg.BandWidthR))
		cf := func(i int) {
			cfg.ConnAmR[i].init()
		}
		forall(cf, len(cfg.ConnAmR))
		tf := func(i int) {
			cfg.TimeRangeR[i].clock = cfg.clock
		}
		forall(tf, len(cfg.TimeRangeR))

		if e == nil {
			cfg.crypt, e = NewCrypt()
		}
	}

	if e == nil {
		auth := ld.NewLdapWithAcc(cfg.AD.Addr, cfg.AD.Suff, cfg.AD.Bdn,
			cfg.AD.User, cfg.AD.Pass)
		inf := func(i int) {
			initSM(cfg.SessionM[i], cfg.crypt, auth)
		}
		forall(inf, len(cfg.SessionM))
		ib := func(i int) (b bool) {
			e = initGrp(cfg.GroupM[i], srchSI(cfg.SessionM), cfg.AD)
			b = e != nil
			return
		}
		bLnSrch(ib, len(cfg.GroupM))
	}
	if e == nil {
		ib := func(i int) (b bool) {
			e = initDwn(cfg.DownR[i], srchSI(cfg.SessionM), srchGM(cfg.GroupM))
			b = e != nil
			return
		}
		bLnSrch(ib, len(cfg.DownR))
	}
	if e == nil {
		ib := func(i int) (b bool) {
			e = initUsrM(cfg.UserM[i], srchSI(cfg.SessionM))
			return
		}
		bLnSrch(ib, len(cfg.UserM))
	}
	if e == nil {
		ib := func(i int) (b bool) {
			e = cfg.RangeIPM[i].init()
			b = e != nil
			return
		}
		bLnSrch(ib, len(cfg.RangeIPM))
	}
	if e == nil {
		e = initLg(cfg.Logger, srchSI(cfg.SessionM))
	}
	if e == nil {
		cfg.rspec = &simpleRSpec{
			rules: make([][]rule, len(cfg.Rules)),
		}
		ib := func(i int) (r bool) {
			jb := func(j int) (b bool) {
				var rl *rule
				rl, e = cfg.initRule(&cfg.Rules[i][j])
				cfg.rspec.add([]int{i, j}, rl)
				b = e != nil
				return
			}
			r, _ = bLnSrch(jb, len(cfg.Rules[i]))
			return
		}
		bLnSrch(ib, len(cfg.Rules))
	}
	// initialization of:
	// - clock
	// - crypt
	//  - BandWidthR
	//  - ConnAmR
	//  - DownR
	//    - SessionM
	//    - GroupM
	//      - SessionM
	//  - NegR
	//  - IdR
	//  - TimeRangeR
	//  - SessionM
	//  - GroupM
	//  - UserM
	//  - RangeIPM
	//  - Logger
	//  - rspec

	// rules added to cfg.rspec
	if e == nil {
		c = &ProxyCtl{
			adm: cfg,
			PrxFls: &SpecCtx{
				clock:   cfg.clock,
				rs:      cfg.rspec,
				timeout: cfg.DialTimeout,
				lg:      cfg.Logger,
			},
		}
	}
	return
}

func srchSI(sm []*sessionIPM) (si srchIU) {
	si = func(name string) (iu IPUser, e error) {
		ib := func(i int) (b bool) {
			b = sm[i].NameF == name
			return
		}
		b, i := bLnSrch(ib, len(sm))
		if b {
			iu = sm[i]
		} else {
			e = NoMngWithName(name)
		}
		return
	}
	return
}

func srchGM(gm []*groupIPM) (su srchUG) {
	su = func(name string) (ug usrGrp, e error) {
		ib := func(i int) (b bool) {
			b = gm[i].NameF == name
			return
		}
		b, i := bLnSrch(ib, len(gm))
		if b {
			ug = gm[i].getOrUpdate
		} else {
			e = NoMngWithName(name)
		}
		return
	}
	return
}

func (c *config) initRule(rl *jRule) (r *rule, e error) {
	r = &rule{
		unit: rl.Unit,
		span: rl.Span,
		spec: &Spec{
			Iface:    rl.Spec.Iface,
			ProxyURL: rl.Spec.ProxyURL,
			Cr:       make([]ConsR, len(rl.Spec.ConsR)),
		},
	}
	r.urlM, e = regexp.Compile(rl.URLM)
	// search and initialize managers(ConsR and IPMatcher)
	ib := func(i int) (b bool) {
		name := rl.Spec.ConsR[i]
		var v *mng
		v, e = c.search(name, true, false, false)
		if e == nil {
			r.spec.Cr[i] = v.cr
		}
		b = e != nil
		return
	}
	bLnSrch(ib, len(rl.Spec.ConsR))
	// initialized r.spec.Cr ≡ e = nil
	var v *mng
	if e == nil {
		v, e = c.search(rl.IPM, false, true, false)
	}
	if e == nil {
		r.ipM = v.im
	}
	// initialized r.ipm ≡ e = nil
	return
}

func NoMngWithType(name, tpe string) (e error) {
	e = fmt.Errorf("No %s with name %s", tpe, name)
	return
}

func NoMngWithName(name string) (e error) {
	e = fmt.Errorf("No manager with name %s", name)
	return
}

func (c *config) dispatch(cmd *AdmCmd) (r string, e error) {
	adm, _ := checkAdmin(cmd.Secret, c.crypt, c.Admins)
	cmd.IsAdmin = adm != ""
	var v *mng
	v, e = c.search(cmd.Manager, false, false, true)
	if e == nil {
		r, e = v.am.Exec(cmd)
	}
	return
}

type mng struct {
	cr ConsR
	im IPMatcher
	am Admin
}

type nameSrch func(string) (bool, *mng)
type nameSrchI func(string, int) (bool, *mng)

func searchElm(es nameSrchI, n int) (r nameSrch) {
	r = func(name string) (ok bool, v *mng) {
		ib := func(i int) (b bool) {
			b, v = es(name, i)
			return
		}
		ok, _ = bLnSrch(ib, n)
		return
	}
	return
}

// search searches a *mng with the given name and type
// n ⇒ with ConsR type
// m ⇒ with IPMatcher type
// a ⇒ with Admin type
func (c *config) search(name string, n, m, a bool) (v *mng, e error) {
	mngs := []nameSrch{
		searchElm(
			func(m string, i int) (b bool, w *mng) {
				r := c.BandWidthR[i]
				b, w = r.NameF == m, &mng{cr: r, am: r}
				return
			},
			len(c.BandWidthR),
		),
		searchElm(
			func(m string, i int) (b bool, w *mng) {
				r := c.ConnAmR[i]
				b, w = r.NameF == m, &mng{cr: r, am: r}
				return
			},
			len(c.ConnAmR),
		),
		searchElm(
			func(m string, i int) (b bool, w *mng) {
				r := c.DownR[i]
				b, w = r.NameF == m, &mng{cr: r, am: r}
				return
			},
			len(c.DownR),
		),
		searchElm(
			func(m string, i int) (b bool, w *mng) {
				r := c.NegR
				b, w = r.NameF == m, &mng{cr: r}
				return
			},
			1,
		),
		searchElm(
			func(m string, i int) (b bool, w *mng) {
				r := c.IdR
				b, w = r.NameF == m, &mng{cr: r}
				return
			},
			1,
		),
		searchElm(
			func(m string, i int) (b bool, w *mng) {
				r := c.TimeRangeR[i]
				b, w = r.NameF == m, &mng{cr: r, am: r}
				return
			},
			len(c.TimeRangeR),
		),
		searchElm(
			func(m string, i int) (b bool, w *mng) {
				r := c.SessionM[i]
				b, w = r.NameF == m, &mng{im: r, am: r}
				return
			},
			len(c.SessionM),
		),
		searchElm(
			func(m string, i int) (b bool, w *mng) {
				r := c.GroupM[i]
				b, w = r.NameF == m, &mng{im: r, am: r}
				return
			},
			len(c.GroupM),
		),
		searchElm(
			func(m string, i int) (b bool, w *mng) {
				r := c.UserM[i]
				b, w = r.NameF == m, &mng{im: r, am: r}
				return
			},
			len(c.UserM),
		),
		searchElm(
			func(m string, i int) (b bool, w *mng) {
				r := c.RangeIPM[i]
				b, w = r.NameF == m, &mng{im: r, am: r}
				return
			},
			len(c.RangeIPM),
		),
		searchElm(
			func(m string, i int) (b bool, w *mng) {
				b, w = "config" == m, &mng{am: c}
				return
			},
			1,
		),
	}
	msch := func(nm string, i int) (b bool, w *mng) {
		b, w = mngs[i](nm)
		return
	}
	nsch := searchElm(msch, len(mngs))
	var ok bool
	ok, v = nsch(name)
	if ok {
		if n && v.cr == nil {
			e = NoMngWithType(name, "ConsR")
		}
		if m && v.im == nil {
			e = NoMngWithType(name, "IPMatcher")
		}
		if a && v.am == nil {
			e = NoMngWithType(name, "Admin")
		}
	} else {
		e = NoMngWithName(name)
	}
	return
}

func NewProxyCtlFile(file string) (c *ProxyCtl, e error) {
	var fl io.ReadCloser
	fl, e = os.Open(file)
	if e == nil {
		c, e = NewProxyCtl(fl)
	}
	if fl != nil {
		fl.Close()
	}
	return
}

func checkAdmin(secret string, c *Crypt, adms []string) (user string,
	e error) {
	user, e = c.Decrypt(secret)
	if e == nil {
		ib := func(i int) (b bool) {
			b = adms[i] == user
			return
		}
		b, _ := bLnSrch(ib, len(adms))
		if !b {
			e = NoAdmin(user)
		}
	}
	return
}

func NoAdmin(user string) (e error) {
	e = fmt.Errorf("No administrator with name %s", user)
	return
}

func NoCmd(name string) (e error) {
	e = fmt.Errorf("No command with name %s", name)
	return
}

func (c *config) persist(w io.Writer) (e error) {
	rf := func(i int) {
		j := c.rspec.rules[i]
		sr := func(k int) {
			l := j[k]
			r := l.toJRule()
			c.Rules[i][k] = *r
		}
		forall(sr, len(j))
	}
	forall(rf, len(c.rspec.rules))
	n := toml.NewEncoder(w)
	e = n.Encode(c)
	return
}

func (c *config) Exec(cmd *AdmCmd) (r string, e error) {
	if cmd.IsAdmin {
		switch cmd.Cmd {
		case "set-ad":
			c.AD = cmd.AD
			ldap := ld.NewLdapWithAcc(c.AD.Addr, c.AD.Suff, c.AD.Bdn,
				c.AD.User, c.AD.Pass)
			// replace references
			inf := func(i int) {
				j := c.SessionM[i]
				ns := newSessionIPM(j.NameF, c.Admins, c.crypt,
					ldap)
				c.SessionM[i] = ns
				uf := func(k int) {
					l := c.UserM[k]
					if l.NameF == j.NameF {
						l.iu = ns
					}
				}
				forall(uf, len(c.UserM))
				gf := func(k int) {
					l := c.GroupM[k]
					if l.NameF == j.NameF {
						l.ldap = ldap
					}
				}
				forall(gf, len(c.GroupM))
			}
			forall(inf, len(c.SessionM))
		case "get-ad":
			var bs []byte
			bs, e = json.Marshal(c.AD)
			r = string(bs)
		case "set-timeout":
			c.DialTimeout = &cmd.DialTimeout
		case "get-timeout":
			r = c.DialTimeout.String()
		case "add-admin":
			c.Admins = append(c.Admins, cmd.User)
			// references updated since slices are reference types
		case "del-admin":
			ib := func(i int) (b bool) {
				b = c.Admins[i] == cmd.User
				return
			}
			b, i := bLnSrch(ib, len(c.Admins))
			if b {
				c.Admins = append(c.Admins[:i], c.Admins[i+1:]...)
			} else {
				e = NoAdmin(cmd.User)
			}
		case "get-admins":
			var bs []byte
			bs, e = json.Marshal(c.Admins)
			r = string(bs)
		case "add-rule":
			var rl *rule
			rl, e = c.initRule(cmd.Rule)
			if e == nil {
				e = c.rspec.add(cmd.Pos, rl)
			}
		case "del-rule":
			e = c.rspec.delete(cmd.Pos)
		case "show-rules":
			r, e = c.rspec.show()
		default:
			e = NoCmd(cmd.Cmd)
		}
	} else if cmd.Cmd == "show-res" {
		// TODO
	} else {
		e = NoCmd(cmd.Cmd)
	}

	return
}
