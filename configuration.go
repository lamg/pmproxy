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

	for i := 0; e == nil && i != len(rl.Spec.ConsR); i++ {
		name := rl.Spec.ConsR[i]
		consr := []linealSearch{
			&bwSearch{
				sl:   c.BandWidthR,
				name: name,
			},
			&cnSearch{
				sl:   c.ConnAmR,
				name: name,
			},
			&dwSearch{
				sl:   c.DownR,
				name: name,
			},
			&ngSearch{
				sl:   c.NegR,
				name: name,
			},
			&idSearch{
				sl:   c.IdR,
				name: name,
			},
			&trSearch{
				sl:   c.TimeRangeR,
				name: name,
			},
		}
		b := false
		for j := 0; !b && j != len(consr); j++ {
			for k := 0; !b && k != consr[j].len(); k++ {
				var v interface{}
				b, v = consr[j].ok(k)
				r.spec.Cr[i], _ = v.(ConsR)
			}
		}
	}
	if e == nil {
		name := rl.IPM
		ipms := []linealSearch{
			&smSearch{
				sl:   c.SessionM,
				name: name,
			}, &grSearch{
				sl:   c.GroupM,
				name: name,
			}, &usSearch{
				sl:   c.UserM,
				name: name,
			}, &rgSearch{
				sl:   c.RangeIPM,
				name: name,
			},
		}
		b := false
		for j := 0; !b && j != len(ipms); j++ {
			for k := 0; !b && k != ipms[j].len(); k++ {
				var v interface{}
				b, v = ipms[j].ok(k)
				r.ipM, _ = v.(IPMatcher)
			}
		}
	}
	return
}

func (c *config) Exec(cmd *AdmCmd) (r string, e error) {
	// TODO
	// search manager
	// send command
	return
}

func (c *config) search(name string) (ok bool, v interface{}) {
	return
}

type linealSearch interface {
	// the interface{} must be a pointer
	ok(int) (bool, interface{})
	len() int
}

type bwSearch struct {
	sl   []bwCons
	name string
}

func (b *bwSearch) ok(i int) (r bool, v interface{}) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		v = &b.sl[i]
	}
	return
}

func (b *bwSearch) len() (r int) {
	r = len(b.sl)
	return
}

type cnSearch struct {
	sl   []connCons
	name string
}

func (b *cnSearch) ok(i int) (r bool, v interface{}) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		v = &b.sl[i]
	}
	return
}

func (b *cnSearch) len() (r int) {
	r = len(b.sl)
	return
}

type dwSearch struct {
	sl   []dwnCons
	name string
}

func (b *dwSearch) ok(i int) (r bool, v interface{}) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		v = &b.sl[i]
	}
	return
}

func (b *dwSearch) len() (r int) {
	r = len(b.sl)
	return
}

type ngSearch struct {
	sl   *negCons
	name string
}

func (b *ngSearch) ok(i int) (r bool, v interface{}) {
	r = i < 1 && b.sl.Name() == b.name
	if r {
		v = b.sl
	}
	return
}

func (b *ngSearch) len() (r int) {
	r = 1
	return
}

type idSearch struct {
	sl   *idCons
	name string
}

func (b *idSearch) ok(i int) (r bool, v interface{}) {
	r = i < 1 && b.sl.Name() == b.name
	if r {
		v = b.sl
	}
	return
}

func (b *idSearch) len() (r int) {
	r = 1
	return
}

type trSearch struct {
	sl   []trCons
	name string
}

func (b *trSearch) ok(i int) (r bool, v interface{}) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		v = &b.sl[i]
	}
	return
}

func (b *trSearch) len() (r int) {
	r = len(b.sl)
	return
}

type smSearch struct {
	sl   []sessionIPM
	name string
}

func (b *smSearch) ok(i int) (r bool, v interface{}) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		v = &b.sl[i]
	}
	return
}

func (b *smSearch) len() (r int) {
	r = len(b.sl)
	return
}

type grSearch struct {
	sl   []groupIPM
	name string
}

func (b *grSearch) ok(i int) (r bool, v interface{}) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		v = &b.sl[i]
	}
	return
}

func (b *grSearch) len() (r int) {
	r = len(b.sl)
	return
}

type usSearch struct {
	sl   []userIPM
	name string
}

func (b *usSearch) ok(i int) (r bool, v interface{}) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		v = &b.sl[i]
	}
	return
}

func (b *usSearch) len() (r int) {
	r = len(b.sl)
	return
}

type rgSearch struct {
	sl   []rangeIPM
	name string
}

func (b *rgSearch) ok(i int) (r bool, v interface{}) {
	r = i < b.len() && b.sl[i].Name() == b.name
	if r {
		v = &b.sl[i]
	}
	return
}

func (b *rgSearch) len() (r int) {
	r = len(b.sl)
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
