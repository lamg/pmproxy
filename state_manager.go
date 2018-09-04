package pmproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
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
	var strTms []string
	var tms []*time.Duration
	if e == nil {
		strTms, tms = []string{
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
	}
	for i := 0; e == nil && i != len(strTms); i++ {
		*tms[i], e = time.ParseDuration(strTms[i])
	}
	s.Dms, s.Cms, s.CLms, s.MainDet =
		make(map[string]*DMng),
		make(map[string]*CMng),
		make(map[string]*CLMng),
		new(SqDet)
	var files []string
	var vs []interface{}
	if e == nil {
		files, vs = []string{fr.DelayMsFile, fr.ConsMsFile, fr.SessionMsFile,
			fr.ConnLimMsFile, fr.ResDetFile,
		},
			[]interface{}{s.Dms, s.Cms, s.Sms, s.CLms, s.MainDet}
	}
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
		s.updateManagers()
	}
	return
}

func (s *StateMng) updateManagers() {
	// s.MainDet tree is walked using rs as stack
	rs := []*SqDet{s.MainDet}
	for len(rs) != 0 {
		curr := rs[len(rs)-1]
		for _, j := range curr.RDs {
			s.updateResDet(j)
		}
		rs = rs[:len(rs)-1]
		rs = append(rs, curr.SDs...)
	}
}

func (s *StateMng) updateResDet(j *ResDet) {
	if j.Cl != nil {
		cl, ok := s.CLms[j.Cl.Name]
		if ok {
			j.Cl = cl
		} else {
			j.Cl = nil
		}
	}
	if j.Cs != nil {
		cs, ok := s.Cms[j.Cs.Name]
		if ok {
			j.Cs = cs
		} else {
			j.Cs = nil
		}
	}
	if j.Dm != nil {
		dm, ok := s.Dms[j.Dm.Name]
		if ok {
			j.Dm = dm
		} else {
			j.Dm = nil
		}
	}
	if j.Gm.Um.Sm != nil {
		sm, ok := s.Sms[j.Gm.Um.Sm.Name]
		if ok {
			j.Gm.Um.Sm = sm
		} else {
			j.Gm.Um.Sm = nil
		}
	}
	if j.Um.Sm != nil {
		sm, ok := s.Sms[j.Um.Sm.Name]
		if ok {
			j.Um.Sm = sm
		} else {
			j.Um.Sm = nil
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

// PrefixHandler is an h.Handler with the last part of the path
// where it should be served
type PrefixHandler struct {
	Prefix string
	Hnd    h.Handler
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
	// SMngType is the URL variable to send the manager
	// type to be added by SrvAddManager
	SMngType = "smng"
)

// SrvAddManager adds a manager
func (s *StateMng) SrvAddManager(w h.ResponseWriter, r *h.Request) {
	di := mux.Vars(r)
	tpe, ok := di[MngType]
	var e error
	if ok {
		dc := json.NewDecoder(r.Body)
		switch tpe {
		case CMngType:
			cm := new(CMng)
			e = dc.Decode(cm)
			if e == nil {
				s.Cms[cm.Name] = cm
			}
		case DMngType:
			dm := new(DMng)
			e = dc.Decode(dm)
			if e == nil {
				s.Dms[dm.Name] = dm
			}
		case CLMngType:
			clm := new(CLMng)
			e = dc.Decode(clm)
			if e == nil {
				s.CLms[clm.Name] = clm
			}
		default:
			e = UnrecTpe(tpe)
		}
	} else {
		e = NoTypeInfo()
	}
	if e == nil {
		s.updateManagers()
	}
	writeErr(w, e)
}

// UnrecTpe is the unrecognized manager type error, sent when trying
// to add a manager to StateMng
func UnrecTpe(tpe string) (e error) {
	e = fmt.Errorf("Unrecognized manager type %s", tpe)
	return
}

// NoTypeInfo is the error signaled when no type information
// was sent to StateMng.SrvAddManager
func NoTypeInfo() (e error) {
	e = fmt.Errorf("No type information sent for manager")
	return
}

const (
	// MngName is the URL variable for sending the manager name
	// to be deleted
	MngName = "manager_name"
)

// SrvDelManager deletes a manager
func (s *StateMng) SrvDelManager(w h.ResponseWriter, r *h.Request) {
	// TODO
	di := mux.Vars(r)
	name, ok := di[MngName]
	if ok {
		delete(s.Cms, name)
		delete(s.CLms, name)
		delete(s.Dms, name)
		delete(s.Sms, name)
		s.updateManagers()
	}
}

const (
	// Index is the variable name for sending indexes in URLs
	Index = "index"
)

// JSqDet is a JSON representable version of SqDet
type JSqDet struct {
	// Unit: true for "for all", false for "exists"
	Unit bool `json:"unit"`
	// RDs resource determinators
	RDs []*ResDet `json:"rDs"`
	// ChL: children's length
	ChL uint32 `json:"chL"`
}

func toJSqDet(s *SqDet) (q *JSqDet) {
	q = &JSqDet{
		RDs:  s.RDs,
		Unit: s.Unit,
		ChL:  uint32(len(s.SDs)),
	}
	// the amount of children subtrees if not leaf
	// since the tree is walked in preorder the children's indexes
	// is predictible knowing the parent's index
	return
}

// SrvDeterminator serves a determinator identified by the index
// sent in URL (default is 0)
func (s *StateMng) SrvDeterminator(w h.ResponseWriter, r *h.Request) {
	i := reqIndex(r)
	dt := detIndexPreorder(s.MainDet, i)
	var e error
	if dt != nil {
		v := toJSqDet(dt)
		var bs []byte
		bs, e = json.Marshal(v)
		if e == nil {
			w.Write(bs)
		}
	} else {
		e = NoDetFound()
	}
	writeErr(w, e)
}

// SrvAddResDet adds a ResDet
func (s *StateMng) SrvAddResDet(w h.ResponseWriter, r *h.Request) {
	i := reqIndex(r)
	bs, e := ioutil.ReadAll(r.Body)
	rd := new(ResDet)
	if e == nil {
		e = json.Unmarshal(bs, rd)
	}
	if e == nil {
		rt := detIndexPreorder(s.MainDet, i)
		if rt != nil {
			rt.RDs = append(rt.RDs, rd)
		} else {
			e = NoDetFound()
		}
	}
	writeErr(w, e)
}

// SrvAddSqDet adds a SqDet
func (s *StateMng) SrvAddSqDet(w h.ResponseWriter, r *h.Request) {
	i := reqIndex(r)
	bs, e := ioutil.ReadAll(r.Body)
	rd := new(SqDet)
	if e == nil {
		e = json.Unmarshal(bs, rd)
	}
	if e == nil {
		rt := detIndexPreorder(s.MainDet, i)
		if rt != nil {
			rt.SDs = append(rt.SDs, rd)
		} else {
			e = NoDetFound()
		}
	}
	writeErr(w, e)
}

func detIndexPreorder(s *SqDet, n uint32) (d *SqDet) {
	ds, i := []*SqDet{s}, uint32(0)
	d = ds[0]
	for i != n && len(ds) != 0 {
		d = ds[len(ds)-1]
		ds = append(ds[:len(ds)-1], d.SDs...)
		i = i + 1
	}
	if i != n {
		d = nil
	}
	return
}

func reqIndex(r *h.Request) (i uint32) {
	di := mux.Vars(r)
	ind, ok := di[Index]
	if ok {
		fmt.Sscan(ind, &i)
	}
	return
}

// NoDetFound is the no determinator found error, sent by
// SrvDeterminator
func NoDetFound() (e error) {
	e = fmt.Errorf("No Det found using detIndexPreorder")
	return
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
