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

		for _, j := range cfg.BandWidthR {
			j.init()
		}
		for _, j := range cfg.ConnAmR {
			j.init()
		}
		for _, j := range cfg.TimeRangeR {
			j.clock = cfg.clock
		}

		if e == nil {
			cfg.crypt, e = NewCrypt()
		}
	}

	if e == nil {
		auth := ld.NewLdapWithAcc(cfg.AD.Addr, cfg.AD.Suff, cfg.AD.Bdn,
			cfg.AD.User, cfg.AD.Pass)
		for _, j := range cfg.SessionM {
			initSM(j, cfg.crypt, auth)
		}
		for i := 0; e == nil && i != len(cfg.GroupM); i++ {
			j := cfg.GroupM[i]
			e = initGrp(j, srchSI(cfg.SessionM), cfg.AD)
		}
	}
	for i := 0; e == nil && i != len(cfg.DownR); i++ {
		j := cfg.DownR[i]
		e = initDwn(j, srchSI(cfg.SessionM), srchGM(cfg.GroupM))
	}
	for i := 0; e == nil && i != len(cfg.UserM); i++ {
		j := cfg.UserM[i]
		e = initUsrM(j, srchSI(cfg.SessionM))
	}
	for i := 0; e == nil && i != len(cfg.RangeIPM); i++ {
		j := cfg.RangeIPM[i]
		e = j.init()
	}
	if e == nil {
		e = initLg(cfg.Logger, srchSI(cfg.SessionM))
	}
	if e == nil {
		cfg.rspec = &simpleRSpec{
			rules: make([][]rule, len(cfg.Rules)),
		}
		for i := 0; e == nil && i != len(cfg.Rules); i++ {
			for j := 0; e == nil && j != len(cfg.Rules[i]); j++ {
				var rl *rule
				rl, e = cfg.initRule(&cfg.Rules[i][j])
				cfg.rspec.add([]int{i, j}, rl)
			}
		}
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
		b, i := false, 0
		for !b && i != len(sm) {
			b = sm[i].NameF == name
			if !b {
				i = i + 1
			}
		}
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
		b, i := false, 0
		for !b && i != len(gm) {
			b = gm[i].NameF == name
			if !b {
				i = i + 1
			}
		}
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

	for i := 0; e == nil && i != len(rl.Spec.ConsR); i++ {
		name := rl.Spec.ConsR[i]
		var v *mng
		v, e = c.search(name, true, false, false)
		if e == nil {
			r.spec.Cr[i] = v.cr
		}
	}
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
		ok = false
		for i := 0; !ok && i != n; i++ {
			ok, v = es(name, i)
		}
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
		b := false
		for i := 0; !b && i != len(adms); i++ {
			b = adms[i] == user
		}
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

func (c *config) Persist(w io.Writer) (e error) {
	for i, j := range c.rspec.rules {
		for k, l := range j {
			r := l.toJRule()
			c.Rules[i][k] = *r
		}
	}
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
			for i, j := range c.SessionM {
				ns := newSessionIPM(j.NameF, c.Admins, c.crypt,
					ldap)
				c.SessionM[i] = ns
				for _, k := range c.UserM {
					if k.NameF == j.NameF {
						k.iu = ns
					}
				}
				for _, k := range c.GroupM {
					if k.NameF == j.NameF {
						k.ldap = ldap
					}
				}
			}
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
			b, i := false, 0
			for !b && i != len(c.Admins) {
				b = c.Admins[i] == cmd.User
				if !b {
					i = i + 1
				}
			}
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
