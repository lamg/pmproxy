package pmproxy

import (
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/lamg/clock"
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
	ADConf *adConf   `toml: "adConf"`

	// arrays of TOML representations of all IPMatcher and ConsR
	// implementations
	BandWidthR []bwCons   `toml: "bandWidthR"`
	ConnAmR    []connCons `toml: "connAmR"`
	DownR      []dwnCons  `toml: "downR"`
	NegR       *negCons   `toml: "negR"`
	IdR        *idCons    `toml: "idR"`
	TimeRangeR []trCons   `toml: "timeRangeR"`

	SessionM []sessionIPM `toml: "sessionM"`
	GroupM   []groupIPM   `toml: "groupM"`
	UserM    []userIPM    `toml: "userM`
	RangeIPM []rangeIPM   `toml: "rangeM"`

	DialTimeout time.Duration `toml: "dialTimeout"`

	crypt *Crypt
	rspec *simpleRSpec
	clock clock.Clock
}

func NewProxyCtl(rd io.Reader) (c *ProxyCtl, e error) {
	cfg := new(config)
	_, e = toml.DecodeReader(rd, cfg)
	if e == nil {
		cfg.crypt, e = NewCrypt()
	}
	if e == nil {
		cfg.clock = new(clock.OSClock)
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
	// rules added to cfg.rspec
	var lg *logger
	if e == nil {
		lg, e = newLogger("pmproxy")
	}
	if e == nil {
		c = &ProxyCtl{
			adm: cfg,
			PrxFls: &SpecCtx{
				clock:   cfg.clock,
				rs:      cfg.rspec,
				timeout: cfg.DialTimeout,
				lg:      lg,
			},
		}
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

	if e == nil {
		for i := 0; i != len(rl.Spec.ConsR); i++ {
			name := rl.Spec.ConsR[i]
			ok, v := c.search(name)
			if ok {
				r.spec.Cr[i], ok = v.(ConsR)
				if !ok {
					e = NoMngWithType(name, "ConsR")
				}
			} else {
				e = NoMngWithName(name)
			}
		}
		// initialized r.spec.ConsR
	}
	if e == nil {
		ok, v := c.search(rl.IPM)
		if ok {
			r.ipM, ok = v.(IPMatcher)
			if !ok {
				e = NoMngWithType(rl.IPM, "IPMatcher")
			}
		} else {
			e = NoMngWithName(rl.IPM)
		}
		// initialized r.ipm
	}
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

func (c *config) Exec(cmd *AdmCmd) (r string, e error) {
	// TODO
	// search manager
	// send command
	return
}

type nameSrch func(string) (bool, interface{})
type nameSrchI func(string, int) (bool, interface{})

func searchElm(es nameSrchI, n int) (r nameSrch) {
	r = func(name string) (ok bool, v interface{}) {
		ok = false
		for i := 0; !ok && i != n; i++ {
			ok, v = es(name, i)
		}
		return
	}
	return
}

func (c *config) search(name string) (ok bool, v interface{}) {
	mngs := []nameSrch{
		searchElm(
			func(m string, i int) (b bool, w interface{}) {
				r := &c.BandWidthR[i]
				b, w = r.NameF == m, r
				return
			},
			len(c.BandWidthR),
		),
		searchElm(
			func(m string, i int) (b bool, w interface{}) {
				r := &c.ConnAmR[i]
				b, w = r.NameF == m, r
				return
			},
			len(c.ConnAmR),
		),
		searchElm(
			func(m string, i int) (b bool, w interface{}) {
				r := &c.DownR[i]
				b, w = r.NameF == m, r
				return
			},
			len(c.DownR),
		),
		searchElm(
			func(m string, i int) (b bool, w interface{}) {
				r := c.NegR
				b, w = r.NameF == m, r
				return
			},
			1,
		),
		searchElm(
			func(m string, i int) (b bool, w interface{}) {
				r := c.IdR
				b, w = r.NameF == m, r
				return
			},
			1,
		),
		searchElm(
			func(m string, i int) (b bool, w interface{}) {
				r := &c.TimeRangeR[i]
				b, w = r.NameF == m, r
				return
			},
			len(c.TimeRangeR),
		),
		searchElm(
			func(m string, i int) (b bool, w interface{}) {
				r := &c.SessionM[i]
				b, w = r.NameF == m, r
				return
			},
			len(c.SessionM),
		),
		searchElm(
			func(m string, i int) (b bool, w interface{}) {
				r := &c.GroupM[i]
				b, w = r.NameF == m, r
				return
			},
			len(c.GroupM),
		),
		searchElm(
			func(m string, i int) (b bool, w interface{}) {
				r := &c.UserM[i]
				b, w = r.NameF == m, r
				return
			},
			len(c.UserM),
		),
		searchElm(
			func(m string, i int) (b bool, w interface{}) {
				r := &c.RangeIPM[i]
				b, w = r.NameF == m, r
				return
			},
			len(c.RangeIPM),
		),
	}
	msch := func(nm string, i int) (b bool, w interface{}) {
		b, w = mngs[i](nm)
		return
	}
	nsch := searchElm(msch, len(mngs))
	ok, v = nsch(name)
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
