package pmproxy

import (
	"github.com/BurntSushi/toml"
	"github.com/lamg/clock"
	ld "github.com/lamg/ldaputil"
	"io"
	"os"
	"sync"
	"time"
)

type Config struct {
	Rules  [][]JRule `toml: "rules"`
	Admins []string  `toml: "admins"`
	ADConf *ADConf   `toml:"adConf"`

	// arrays of TOML representations of all IPMatcher and ConsR
	// implementations
	BandWidthR []bwCons   `toml: "bandWidthR"`
	ConnAmR    []connCons `toml: "connAmR"`
	DownR      []dwnCons  `toml: "downR"`
	NegR       *negCons   `toml: "negR"`
	IdR        *idCons    `toml: "idR"`
	TimeRangeR []trCons   `toml: "timeRangeR"`

	SessionM []SessionMng `toml: "sessionM"`
	GroupM   []groupIPM   `toml: "groupM"`
	UserM    []userIPM    `toml: "userM`
	RangeIPM []rangeIPM   `toml: "rangeM"`

	DialTimeout time.Duration `toml: "dialTimeout"`
}

func NewProxyCtl(rd io.Reader) (c *ProxyCtl, e error) {
	cfg := new(Config)
	_, e = toml.DecodeReader(rd, cfg)
	var cr *Crypt
	if e == nil {
		cr, e = NewCrypt()
	}
	var mng *manager
	var rspec *simpleRSpec
	var cl clock.Clock
	if e == nil {
		cl = new(clock.OSClock)
		rspec = &simpleRSpec{
			rules: make([][]Rule, 0),
		}
		mng = &manager{
			clock:  cl,
			crypt:  cr,
			adcf:   cfg.ADConf,
			admins: cfg.Admins,
			rspec:  rspec,
			mngs:   make(map[string]*Mng),
		}
		initNoErr(mng, cfg, cr, cl)
		e = initRangeIPM(mng, cfg)
	}
	if e == nil {
		e = initDownR(mng, cfg, cl)
	}
	if e == nil {
		e = initGroupM(mng, cfg)
	}
	if e == nil {
		e = initUserM(mng, cfg)
	}
	// managers added
	// rules added
	if e == nil {
		c = &ProxyCtl{
			clock: cl,
			adm:   mng,
			rp:    rspec,
			prxFls: &SpecCtx{
				clock:   cl,
				rs:      rspec,
				Timeout: cfg.DialTimeout,
			},
		}
	}
	return
}

// initializes cfg.BandWidthR, cfg.ConnAmR, cfg.TimeRangeR,
// cfg.SessionM
func initNoErr(mng *manager, cfg *Config, cr *Crypt, cl clock.Clock) {
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
		j.auth = ld.NewLdapWithAcc(ac.addr, ac.suff, ac.bdn,
			ac.user, ac.pass)
		mng.mngs[j.Name()] = &Mng{
			Admin: &j,
			IPM:   &j,
		}
	}
}

// initializes cfg.RangeIPM or error
func initRangeIPM(mng *manager, cfg *Config) (e error) {
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
func initDownR(mng *manager, cfg *Config, cl clock.Clock) (e error) {
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

func initGroupM(mng *manager, cfg *Config) (e error) {
	for i := 0; e == nil && i != len(cfg.GroupM); i++ {
		j := cfg.GroupM[i]
		ac := cfg.ADConf
		j.ldap = ld.NewLdapWithAcc(ac.addr, ac.suff, ac.bdn,
			ac.user, ac.pass)
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

func initUserM(mng *manager, cfg *Config) (e error) {
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
