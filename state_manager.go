package pmproxy

import (
	"io"
	"io/ioutil"
	h "net/http"
	"os"
	"time"

	"github.com/gorilla/mux"

	"gopkg.in/yaml.v2"
)

// StateMng loads and writes the proxy state automatically to disk
type StateMng struct {
	File string

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

	// delay manager
	// consumption manager
	// session manager
	// connection limit manager
	// general resource determinator

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

	ResDetFile string `yaml:"resDetFile"`
}

// NewStateMng creates a StateMng instance using information
// in file
func NewStateMng(file string) (s *StateMng, e error) {
	s = &StateMng{
		File: file,
	}
	var fl io.ReadCloser
	fl, e = os.Open(file)
	var bs []byte
	if e == nil {
		bs, e = ioutil.ReadAll(fl)
		fl.Close()
	}
	var fr *FileRepr
	if e == nil {
		fr = new(FileRepr)
		e = yaml.Unmarshal(bs, fr)
	}
	if e == nil {
		s.WebAddr = fr.WebAddr
		s.ProxyAddr = fr.ProxyAddr
		s.CertFile = fr.CertFile
		s.KeyFile = fr.KeyFile
		s.WebReadTimeout, e = time.ParseDuration(fr.WebReadTimeout)
	}
	if e == nil {
		s.WebWriteTimeout, e = time.ParseDuration(fr.WebWriteTimeout)
	}
	if e == nil {
		s.ProxyReadTimeout, e = time.ParseDuration(fr.ProxyReadTimeout)
	}
	if e == nil {
		s.ProxyWriteTimeout, e = time.ParseDuration(fr.ProxyWriteTimeout)
	}
	return
}

// WebInterface returns the h.Handler used to serve the web interface
func (s *StateMng) WebInterface() (hn h.Handler) {
	router := mux.NewRouter()
	// TODO
	hn = router
	return
}

func (s *StateMng) ResourceDeterminators() (d []Det) {
	// TODO
	return
}
