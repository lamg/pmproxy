package pmproxy

import (
	"net"
	h "net/http"
	"net/url"
	"time"
)

type CfDet struct {
	Cf  int
	Opt []Det
	// access exception list
}

func (c *CfDet) Det(r *h.Request, d time.Time) (ok bool, e error) {
	ok, e = BLS(c.Opt, r, d)
	return
}

type IfaceDet struct {
	Iface string
	Opt   []Det
}

func (c *IfaceDet) Det(r *h.Request, d time.Time) (ok bool, e error) {
	ok, e = BLS(c.Opt, r, d)
	return
}

type ProxyDet struct {
	Proxy *url.URL
	Opt   []Det
}

func (c *ProxyDet) Det(r *h.Request, d time.Time) (ok bool, e error) {
	ok, e = BLS(c.Opt, r, d)
	return
}

type ThrDet struct {
	Thr float64
	Opt []Det
}

func (c *ThrDet) Det(r *h.Request, d time.Time) (ok bool, e error) {
	ok, e = BLS(c.Opt)
	return
}

type QuotaDet struct {
	Quota  uint64
	UsrDet *SMng
	QtM    *QMng
}

func (c *QuotaDet) Det(r *h.Request, d time.Time) (ok bool, e error) {
	ok, e = c.UsrDet.Det(r, d)
	if ok && e == nil {
		c.Quota, e = c.QtM.Get(c.UsrDet.User)
	}
	return
}

type ConsDet struct {
	Cons   *uint64
	CsM    *CMng
	UsrDet *SMng
}

func (c *ConsDet) Det(r *h.Request, d time.Time) (ok bool, e error) {
	ok, e = c.UsrDet.Det(r, d)
	if ok && e == nil {
		c.Cons, ok = c.CsM.Get(c.UsrDet.User)
	}
	return
}

type ConSpec struct {
	Proxy    *url.URL
	Iface    string
	Cf       int
	Throttle float64
	Quota    uint64
	Cons     *uint64
}

// ResDet determines a group and an individual
// corresponding to the passed parameters
type ResDet interface {
	Det(*h.Request, time.Time) (bool, error)
}

type dBool struct {
	dt Det
	r  *h.Request
	t  time.Time
	e  error
}

func (d *dBool) V() (b bool) {
	b, d.e = d.dt.Det(d.r, d.t)
	b = b || d.e != nil
	return
}

func BLS(d []Det, r *h.Request, t time.Time) (b bool, e error) {
	ds := make([]Bool, len(d))
	for i, j := range d {
		ds[i] = &dBool{dt: j, r: r, t: t}
	}
	b, i := BoundedLinearSearch(ds)
	if b {
		e = ds[i].(*dBool).e
		b = e == nil
	}
	return
}
