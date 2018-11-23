package pmproxy

import (
	"github.com/BurntSushi/toml"
	"github.com/lamg/clock"
	"io"
	"os"
)

type Config struct {
	Rules  [][]JRule
	Admins []string
	ADConf *ADConf

	// arrays of TOML representations of all IPMatcher and ConsR
	// implementations
	BandWidthR []bwCons
	ConnAmR    []connCons
	DownR      []dwnCons
	NegR       *negCons
	IdR        *idCons
	TimeRangeR []trCons

	SessionM []SessionMng
	GroupM   []groupIPM
	UserM    []userIPM

	DialTimeout time.Duration
}

func NewProxyCtl(rd io.Reader) (c *ProxyCtl, e error) {
	cfg := new(Config)
	_, e = toml.DecodeReader(rd, cfg)
	var cr *Crypt
	if e == nil {
		cr, e = NewCrypt()
	}
	if e == nil {
		cl := new(clock.OSClock)

		rspec := &simpleRSpec{
			rules: make([][]Rule, 0),
		}
		mng := &manager{
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
		for _, j := range cfg.DownR {

		}
		// managers added
		// rules added

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
