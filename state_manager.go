package pmproxy

import (
	"encoding/json"
	"io/ioutil"
	h "net/http"
	"time"

	"github.com/gorilla/mux"

	fs "github.com/lamg/filesystem"
	"gopkg.in/yaml.v2"
)

// StateMng loads and writes the proxy state automatically to disk
type StateMng struct {
	File string
	FSys fs.FileSystem

	// web interface fields
	WebAddr         string
	WebReadTimeout  time.Duration
	WebWriteTimeout time.Duration
	CertFile        string
	KeyFile         string

	// proxy fields
	ProxyAddr         string
	ProxyReadTimeout  time.Duration
	ProxyWriteTimeout time.Duration

	// delay managers
	Dms map[string]*DMng
	// consumption managers
	Cms map[string]*CMng
	// session manager
	Sms map[string]*SMng
	// connection limit manager
	CLms map[string]*CLMng

	// general resource determinator
	MainDet *SqDet
}

// FileRepr is the type used for decoding and encoding a StateMng
type FileRepr struct {
	// web interface fields
	WebAddr         string `yaml:"webAddr"`
	WebReadTimeout  string `yaml:"webReadTimeout"`
	WebWriteTimeout string `yaml:"webWriteTimeout"`
	CertFile        string `yaml:"certFile"`
	KeyFile         string `yaml:"keyFile"`

	// proxy fields
	ProxyAddr         string `yaml:"proxyAddr"`
	ProxyReadTimeout  string `yaml:"proxyReadTimeout"`
	ProxyWriteTimeout string `yaml:"proxyWriteTimeout"`

	// delay, consumption, session, connection limit managers files
	DelayMsFile   string `yaml:"delayMsFile"`
	ConsMsFile    string `yaml:"consMsFile"`
	SessionMsFile string `yaml:"sessionMsFile"`
	ConnLimMsFile string `yaml:"connLimMsFile"`

	// main resource determinator file
	ResDetFile string `yaml:"resDetFile"`
}

// NewStateMng creates a StateMng instance using information
// in file
func NewStateMng(file string, stm fs.FileSystem) (s *StateMng, e error) {
	s = &StateMng{
		File: file,
		FSys: stm,
	}
	var bs []byte
	bs, e = stm.ReadFile(file)
	var fr *FileRepr
	if e == nil {
		fr = new(FileRepr)
		e = yaml.Unmarshal(bs, fr)
	}
	if e == nil {
		s.WebAddr, s.ProxyAddr, s.CertFile, s.KeyFile =
			fr.WebAddr,
			fr.ProxyAddr,
			fr.CertFile,
			fr.KeyFile
	}
	strTms, tms := []string{
		fr.WebReadTimeout,
		fr.WebWriteTimeout,
		fr.ProxyReadTimeout,
		fr.ProxyWriteTimeout,
	}, []*time.Duration{
		&s.WebReadTimeout,
		&s.WebWriteTimeout,
		&s.ProxyReadTimeout,
		&s.ProxyWriteTimeout,
	}
	for i := 0; e == nil && i != len(strTms); i++ {
		*tms[i], e = time.ParseDuration(strTms[i])
	}
	s.Dms, s.Cms, s.CLms, s.MainDet =
		make(map[string]*DMng),
		make(map[string]*CMng),
		make(map[string]*CLMng),
		new(SqDet)
	files, vs := []string{fr.DelayMsFile, fr.ConsMsFile, fr.SessionMsFile,
		fr.ConnLimMsFile, fr.ResDetFile,
	},
		[]interface{}{s.Dms, s.Cms, s.Sms, s.CLms, s.MainDet}
	for i := 0; e == nil && i != len(files); i++ {
		e = decode(files[i], vs[i])
	}
	return
}

func decode(file string, v interface{}) (e error) {
	var bs []byte
	bs, e = ioutil.ReadFile(file)
	if e == nil {
		e = json.Unmarshal(bs, v)
	}
	return
}

// WebInterface returns the h.Handler used to serve the web interface
func (s *StateMng) WebInterface() (hn h.Handler) {
	router := mux.NewRouter()
	// TODO
	for _, v := range s.Dms {
		ph := v.PrefixHandler()
		router.Handle(ph.Prefix, ph.Hnd)
	}
	for _, v := range s.Cms {
		ph := v.PrefixHandler()
		router.Handle(ph.Prefix, ph.Hnd)
	}
	for _, v := range s.CLms {
		ph := v.PrefixHandler()
		router.Handle(ph.Prefix, ph.Hnd)
	}
	for _, v := range s.Sms {
		ph := v.PrefixHandler()
		router.Handle(ph.Prefix, ph.Hnd)
		ah := v.AdminHandler()
		router.Handle(ah.Prefix, ah.Hnd)
	}
	hn = router
	return
}

// ResourceDeterminators creates the determinators for use
// within Connector
func (s *StateMng) ResourceDeterminators() (d []Det) {
	// TODO
	d = []Det{s.MainDet}
	return
}
