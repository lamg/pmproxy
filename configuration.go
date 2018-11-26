package pmproxy

import (
	"github.com/BurntSushi/toml"
	"github.com/lamg/clock"
	ld "github.com/lamg/ldaputil"
	"io"
	"os"
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
			ADConf: cfg.ADConf,
			admins: cfg.Admins,
			rspec:  rspec,
			mngs:   make(map[string]*Mng),
		}
		// TODO
		for _, j := range cfg.BandWidthR {
			j.init()
			mng.mngs[j.Name()] = j
		}
		for _, j := range cfg.ConnAmR {
			j.init()
			mng.mngs[j.Name()] = j
		}
		for _, j := range cfg.TimeRangeR {
			j.clock = cl
		}
		for _, j := range cfg.SessionM {
			j.sessions = new(sync.Map)
			j.crypt = cr
			ac := cfg.ADConf
			j.ADConf = cfg.ADConf
			j.auth = ld.NewLdapWithAcc(ac.addr, ac.suff, ac.bdn,
				ac.user, ac.pass)
			mng.mngs[j.Name()] = j
		}
		// initializing cfg.DownR requires initializing session
		// managers
		for i := 0; e == nil && i != len(cfg.DownR); i++ {
			j := cfg.DownR[i]
			j.cl = cl
			j.usrCons = new(sync.Map)
			var ok bool
			j.iu, ok = mng.mngs[j.IPUser]
			if !ok {
				e = NoMngWithName(j.IPUser)
			}
		}
		// managers added
		// rules added
	}
	if e == nil {
		for i := 0; e == nil && i != len(cfg.GroupM); i++ {
			j := cfg.GroupM[i]
			ac := cfg.ADConf
			j.ldap = ld.NewLdapWithAcc(ac.addr, ac.suff, ac.bdn,
				ac.user, ac.pass)
			j.cache = new(sync.Map)
			var ok bool
			j.ipUser, ok = mng.mngs[j.IPUser]
			if !ok {
				e = NoMngWithName(j.IPUser)
			}
		}
	}
	if e == nil {
		for i := 0; e == nil && i != len(cfg.UserM); i++ {
			j := cfg.UserM[i]
			var ok bool
			j.iu, ok = mng.mngs[j.IPUser]
			if !ok {
				e = NoMngWithName(j.IPUser)
			}
		}
	}
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
