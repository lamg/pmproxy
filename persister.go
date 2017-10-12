package pmproxy

import (
	"github.com/lamg/errors"
	w "github.com/lamg/wfact"
	"io"
	"time"
)

// Persister persists objects that can be represented
// as an io.Reader, every certain amount of time, starting
// in a supplied date, to a file abstracted by a
// WriterFct
type Persister struct {
	wf w.WriterFct
	dt time.Time
	iv time.Duration
}

// NewPersister creates a Persister struct
func NewPersister(wf w.WriterFct, dt time.Time,
	iv time.Duration) (p *Persister) {
	p = &Persister{wf, dt, iv}
	return
}

func (p *Persister) persistNow(r io.Reader) (e *errors.Error) {
	p.wf.NextWriter()
	e = p.wf.Err()
	if e == nil {
		_, ec := io.Copy(p.wf.Current(), r)
		e = errors.NewForwardErr(ec)
	}
	return
}

// Persist persists the content of r as described previously
func (p *Persister) Persist(r io.Reader) (b bool,
	e *errors.Error) {
	t := newTime(p.dt, p.iv)
	b = t != p.dt
	if b {
		p.dt, e = t, p.persistNow(r)
	}
	return
}

// time.Now() - d > i ≡ n ≠ d
// n ≠ d ⇒ n - d < i
func newTime(d time.Time, i time.Duration) (n time.Time) {
	var nw time.Time
	var ta time.Duration
	nw = time.Now()
	// { nw - d < 290 years (by time.Duration's doc.)}
	var ci time.Duration
	ci = nw.Sub(d)
	// { cintv: interval between now and the last}
	ta = ci / i
	n = d.Add(i * ta)
	return
}
