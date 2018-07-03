package pmproxy

import (
	"fmt"
	"io"
	h "net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/lamg/clock"
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
		e = decodeYAML(files[i], vs[i], stm)
		if e != nil {
			_, ok := e.(*os.PathError)
			if ok {
				var fl afero.File
				fl, e = stm.Create(files[i])
				if e == nil {
					fl.Close()
				}
			}
		}
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

func decodeYAML(file string, v interface{}, stm afero.Fs) (e error) {
	var bs []byte
	bs, e = afero.ReadFile(stm, file)
	if e == nil {
		e = yaml.Unmarshal(bs, v)
		if e != nil {
			e = fmt.Errorf("%s: %s", file, e.Error())
		}
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

// Connector returns a connector with the current configuration
func (s *StateMng) Connector() (c *Connector) {
	c = &Connector{
		Cl: new(clock.OSClock),
		Dl: new(OSDialer),
		Rd: s.MainDet,
	}
	return
}

const (
	// MngType is the URL variable to send the manager
	// type to be added by SrvAddManager
	MngType = "type"
	// CMngType is the URL variable to send the manager
	// type to be added by SrvAddManager
	CMngType = "cmng"
	// DMngType is the URL variable to send the manager
	// type to be added by SrvAddManager
	DMngType = "dmng"
	// CLMngType is the URL variable to send the manager
	// type to be added by SrvAddManager
	CLMngType = "clmng"
)

// SrvAddManager adds a manager
func (s *StateMng) SrvAddManager(w h.ResponseWriter, r *h.Request) {
	// TODO
	di := mux.Vars(r)
	tpe, ok := di[MngType]
	var e error
	if ok {
		switch tpe {
		case CMngType:
		case DMngType:
		case CLMngType:
		default:
			e = fmt.Errorf("Unrecognized manager type %s", tpe)
		}
	}
	writeErr(w, e)
}

// SrvDelManager deletes a manager
func (s *StateMng) SrvDelManager(w h.ResponseWriter, r *h.Request) {
	// TODO
}

// PersistState updates the content of state files
func (s *StateMng) PersistState() {
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
