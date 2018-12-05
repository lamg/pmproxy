package pmproxy

import (
	"github.com/BurntSushi/toml"
	"github.com/lamg/clock"
	ld "github.com/lamg/ldaputil"
	"io"
	"os"
	"regexp"
	"sync"
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
	var rspec *simpleRSpec
	if e == nil {
		cfg.clock = new(clock.OSClock)
		cfg.rspec = &simpleRSpec{
			rules: make([][]rule, len(cfg.Rules)),
		}
		for i := 0; e == nil && i != len(cfg.Rules); i++ {
			for j := 0; e == nil && j != len(cfg.Rules[i]); j++ {
				var rl *rule
				rl, e = cfg.initRule(cfg.Rules[i][j])
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

type linealSearch interface {
	// the interface{} must be a pointer
	ok(uint, interface{}) bool
	len() uint
}

type bwSearch struct {
	sl   []bwCons
	name string
}

func (b *bwSearch) ok(i uint, v interface{}) (r bool) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		*v = b.sl[i]
	}
	return
}

func (b *bwSearch) len() (r uint) {
	r = uint(len(b.sl))
	return
}

type cnSearch struct {
	sl   []connCons
	name string
}

func (b *cnSearch) ok(i uint, v interface{}) (r bool) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		*v = b.sl[i]
	}
	return
}

func (b *cnSearch) len() (r uint) {
	r = uint(len(b.sl))
	return
}

type dwSearch struct {
	sl   []dwnCons
	name string
}

func (b *dwSearch) ok(i uint, v interface{}) (r bool) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		*v = b.sl[i]
	}
	return
}

func (b *dwSearch) len() (r uint) {
	r = uint(len(b.sl))
	return
}

type ngSearch struct {
	sl   *negCons
	name string
}

func (b *ngSearch) ok(i uint, v interface{}) (r bool) {
	r = i < 1 && b.sl.Name() == b.name
	if r {
		*v = b.negCons
	}
	return
}

func (b *ngSearch) len() (r uint) {
	r = uint(1)
	return
}

type idSearch struct {
	sl   *idCons
	name string
}

func (b *idSearch) ok(i uint, v interface{}) (r bool) {
	r = i < 1 && b.sl.Name() == b.name
	if r {
		*v = b.negCons
	}
	return
}

func (b *idSearch) len() (r uint) {
	r = uint(1)
	return
}

type trSearch struct {
	sl   []trCons
	name string
}

func (b *trSearch) ok(i uint, v interface{}) (r bool) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		*v = b.sl[i]
	}
	return
}

func (b *trSearch) len() (r uint) {
	r = uint(len(b.sl))
	return
}

type smSearch struct {
	sl   []sessionIPM
	name string
}

func (b *smSearch) ok(i uint, v interface{}) (r bool) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		*v = b.sl[i]
	}
	return
}

func (b *smSearch) len() (r uint) {
	r = uint(len(b.sl))
	return
}

type grSearch struct {
	sl   []groupIPM
	name string
}

func (b *grSearch) ok(i uint, v interface{}) (r bool) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		*v = b.sl[i]
	}
	return
}

func (b *grSearch) len() (r uint) {
	r = uint(len(b.sl))
	return
}

type usSearch struct {
	sl   []userIPM
	name string
}

func (b *usSearch) ok(i uint, v interface{}) (r bool) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		*v = b.sl[i]
	}
	return
}

func (b *usSearch) len() (r uint) {
	r = uint(len(b.sl))
	return
}

type rgSearch struct {
	sl   []rangeIPM
	name string
}

func (b *rgSearch) ok(i uint, v interface{}) (r bool) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		*v = b.sl[i]
	}
	return
}

func (b *rgSearch) len() (r uint) {
	r = uint(len(b.sl))
	return
}

func (c *config) initRule(rl *jRule) (r *rule, e error) {
	r = &rule{
		unit: rl.Unit,
		span: rl.Span,
		spec: &Spec{
			Iface:    rl.Spec.Iface,
			ProxyURL: rl.Spec.ProxyURL,
			ConsR:    make([]ConsR, len(rl.Spec.ConsR)),
		},
	}
	r.urlM, e = regexp.Compile(rl.URLM)
	// search and initialize managers(ConsR and IPMatcher)

	for i := 0; e == nil && i != len(rl.Spec.ConsR); i++ {
		consr := []linealSearch{c.BandWidthR, c.ConnAmR, c.DownR,
			c.NegR, c.IdR, c.TimeRangeR,
		}
		b := false
		for j := 0; !b && j != len(consr); j++ {
			for k := 0; !b && k != consr[j].len(); k++ {
				b = consr[j].ok(k, &r.spec.ConsR[i])
			}
		}
	}
	if e == nil {
		ipms := []linealSearch{c.SessionM, c.GroupM, c.UserM,
			c.RangeIPM,
		}
		b := false
		for j := 0; !b && j != len(ipms); j++ {
			for k := 0; !b && k != ipms[j].len(); k++ {
				b = ipms[j].ok(k, &r.ipM)
			}
		}
	}

	return
}

// initializes cfg.BandWidthR, cfg.ConnAmR, cfg.TimeRangeR,
// cfg.SessionM
func initNoErr(mng *manager, cfg *config, cr *Crypt, cl clock.Clock) {
	for _, j := range cfg.BandWidthR {
		j.init()
		mng.mngs[j.Name()] = &Mng{
			Admin: &j,
			Cr:    &j,
		}
	}
	for _, j := range cfg.ConnAmR {
		j.init()
		mng.mngs[j.Name()] = &Mng{
			Admin: &j,
			Cr:    &j,
		}
	}
	for _, j := range cfg.TimeRangeR {
		j.clock = cl
		mng.mngs[j.Name()] = &Mng{
			Admin: &j,
			Cr:    &j,
		}
	}
	for _, j := range cfg.SessionM {
		j.sessions = new(sync.Map)
		j.crypt = cr
		ac := cfg.ADConf
		j.ADConf = cfg.ADConf
		j.auth = ld.NewLdapWithAcc(ac.Addr, ac.Suff, ac.Bdn,
			ac.User, ac.Pass)
		mng.mngs[j.Name()] = &Mng{
			Admin: &j,
			IPM:   &j,
		}
	}
}

// initializes cfg.RangeIPM or error
func initRangeIPM(mng *manager, cfg *config) (e error) {
	for i := 0; e == nil && i != len(cfg.RangeIPM); i++ {
		j := cfg.RangeIPM[i]
		e = j.init()
		if e == nil {
			mng.mngs[j.Name()] = &Mng{
				Admin: &j,
				IPM:   &j,
			}
		}
	}
	return
}

// initializes cfg.DownR, requires initializing session managers
func initDownR(mng *manager, cfg *config, cl clock.Clock) (e error) {
	for i := 0; e == nil && i != len(cfg.DownR); i++ {
		j := cfg.DownR[i]
		j.cl = cl
		j.usrCons = new(sync.Map)
		m, ok := mng.mngs[j.IPUser]
		if ok {
			j.iu, ok = m.Admin.(IPUser)
			if !ok {
				e = NoMngWithType(j.IPUser, "IPUser")
			}
		} else {
			e = NoMngWithName(j.IPUser)
		}
		if e == nil {
			mng.mngs[j.Name()] = &Mng{
				Admin: &j,
				Cr:    &j,
			}
		}
	}
	// initialized cfg.DownR or error
	return
}

func initGroupM(mng *manager, cfg *config) (e error) {
	for i := 0; e == nil && i != len(cfg.GroupM); i++ {
		j := cfg.GroupM[i]
		ac := cfg.ADConf
		j.ldap = ld.NewLdapWithAcc(ac.Addr, ac.Suff, ac.Bdn,
			ac.User, ac.Pass)
		j.cache = new(sync.Map)
		m, ok := mng.mngs[j.IPUser]
		if ok {
			j.ipUser, ok = m.Admin.(IPUser)
			if !ok {
				e = NoMngWithType(j.IPUser, "IPUser")
			}
		} else {
			e = NoMngWithName(j.IPUser)
		}
		if e == nil {
			mng.mngs[j.Name()] = &Mng{
				Admin: &j,
				IPM:   &j,
			}
		}
	}
	// initialized cfg.GroupM or error
	return
}

func initUserM(mng *manager, cfg *config) (e error) {
	for i := 0; e == nil && i != len(cfg.UserM); i++ {
		j := cfg.UserM[i]
		m, ok := mng.mngs[j.IPUser]
		if ok {
			j.iu, ok = m.Admin.(IPUser)
			if !ok {
				e = NoMngWithType(j.IPUser, "IPUser")
			}
		} else {
			e = NoMngWithName(j.IPUser)
		}
		if e == nil {
			mng.mngs[j.Name()] = &Mng{
				Admin: &j,
				IPM:   &j,
			}
		}
	}
	// initialized cfg.UserM or error
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
