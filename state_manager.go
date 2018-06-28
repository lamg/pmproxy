package pmproxy

import (
	"encoding/json"
	"io"
	"io/ioutil"
	h "net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/spf13/afero"

	"gopkg.in/yaml.v2"
)

// StateMng loads and writes the proxy state automatically to disk
type StateMng struct {
	File string
	FlR  *FileRepr
	FSys afero.Fs

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

	// following maps have the managers referenced in
	// MainDet children
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
func NewStateMng(file string, stm afero.Fs) (s *StateMng, e error) {
	s = &StateMng{
		File: file,
		FSys: stm,
	}
	var bs []byte
	bs, e = afero.ReadFile(stm, file)
	var fr *FileRepr
	if e == nil {
		fr = new(FileRepr)
		e = yaml.Unmarshal(bs, fr)
	}
	if e == nil {
		s.FlR, s.WebAddr, s.ProxyAddr, s.CertFile, s.KeyFile =
			fr,
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
		decode(files[i], vs[i])
	}
	if e == nil {
		s.initManagers()
	}
	return
}

func (s *StateMng) initManagers() {
	// s.MainDet tree is walked using rs as stack
	rs := []*SqDet{s.MainDet}
	for len(rs) != 0 {
		curr := rs[len(rs)-1]
		for _, j := range curr.RDs {
			s.initResDet(j)
		}
		rs = rs[:len(rs)-1]
		rs = append(rs, curr.SDs...)
	}
}

func (s *StateMng) initResDet(j *ResDet) {
	if j.Cl != nil {
		cl, ok := s.CLms[j.Cl.Name]
		if ok {
			j.Cl = cl
		}
	}
	if j.Cs != nil {
		cs, ok := s.Cms[j.Cs.Name]
		if ok {
			j.Cs = cs
		}
	}
	if j.Dm != nil {
		dm, ok := s.Dms[j.Dm.Name]
		if ok {
			j.Dm = dm
		}
	}
	if j.Gm.Um.Sm != nil {
		sm, ok := s.Sms[j.Gm.Um.Sm.Name]
		if ok {
			j.Gm.Um.Sm = sm
		}
	}
	if j.Um.Sm != nil {
		sm, ok := s.Sms[j.Um.Sm.Name]
		if ok {
			j.Um.Sm = sm
		}
	}
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

// PersistState updates the content of state files
func (s *StateMng) PersistState() {
	//TODO
	s.FlR = &FileRepr{
		WebAddr:           s.WebAddr,
		WebReadTimeout:    s.WebReadTimeout.String(),
		WebWriteTimeout:   s.WebWriteTimeout.String(),
		CertFile:          s.CertFile,
		KeyFile:           s.KeyFile,
		ProxyAddr:         s.ProxyAddr,
		ProxyReadTimeout:  s.ProxyWriteTimeout.String(),
		ProxyWriteTimeout: s.ProxyWriteTimeout.String(),

		DelayMsFile:   s.FlR.DelayMsFile,
		ConsMsFile:    s.FlR.ConsMsFile,
		SessionMsFile: s.FlR.SessionMsFile,
		ConnLimMsFile: s.FlR.ConnLimMsFile,
		ResDetFile:    s.FlR.ResDetFile,
	}
	fls, vs := []string{
		s.File,
		s.FlR.DelayMsFile,
		s.FlR.ConsMsFile,
		s.FlR.ConnLimMsFile,
		s.FlR.ResDetFile,
	}, []interface{}{
		s.FlR,
		s.Dms,
		s.Cms,
		s.CLms,
		s.MainDet,
	}
	var e error
	for i := 0; e == nil && i != len(fls); i++ {
		var fl io.WriteCloser
		fl, e = prep(fls[i], s.FSys)
		if e == nil {
			enc := yaml.NewEncoder(fl)
			e = enc.Encode(vs[i])
			fl.Close()
		}
	}
}

func prep(file string, fsys afero.Fs) (w io.WriteCloser, e error) {
	e = fsys.Rename(file+"~", file)
	if e == nil {
		w, e = fsys.Create(file)
	}
	return
}
