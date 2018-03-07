package pmproxy

import (
	"net"
	h "net/http"
	"net/url"
	"time"
)

type CfDet struct {
	Cf int
	ResDet
}

type StringDet struct {
	Str string
	ResDet
}

type ProxyDet struct {
	Proxy *url.URL
	ResDet
}

type ThrDet struct {
	Thr float64
	ResDet
}

type QuotaDet struct {
	Quota uint64
	QtM   *QMng
	Usr   *StringDet
}

func (c *QuotaDet) Det(r *h.Request, d time.Time) (ok bool, e error) {
	ok, e = c.Usr.Det(r, d)
	if ok && e == nil {
		c.Quota, e = c.QtM.Get(c.Usr.Str)
	}
	return
}

type ConsDet struct {
	Cons *uint64
	CsM  *CMng
	Usr  *StringDet
}

func (c *ConsDet) Det(r *h.Request, d time.Time) (ok bool, e error) {
	ok, e = c.Usr.Det(r, d)
	if ok && e == nil {
		c.Cons, ok = c.CsM.Get(c.Usr.Str)
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

type AndDet struct {
	Ds []ResDet
}

func (d *AndDet) Det(r *h.Request, t time.Time) (b bool, e error) {
	b, i := true, 0
	for b && e == nil && i != len(d.Ds) {
		b, e = d.Ds[i].Det(r, t)
		if b && e == nil {
			i = i + 1
		}
	}
	return
}

type OrDet struct {
	Ds []ResDet
}

func (d *OrDet) Det(r *h.Request, t time.Time) (b bool, e error) {
	b, i := false, 0
	for !b && i != len(d.Ds) {
		b, e = d.Ds[i].Det(r, t)
		if !b {
			i = i + 1
		}
	}
	return
}

type NegDet struct {
	D ResDet
}

func (d *NegDet) Det(r *h.Request, t time.Time) (b bool, e error) {
	b, e = d.D.Det()
	b = !b
	return
}

type RgIPDt struct {
	IPn *net.IPNet
}

func (g *RgIPDt) Det(r *h.Request, t time.Time) (b bool, e error) {
	ip, _, e = net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		ni := net.ParseIP(s)
		if ni != nil {
			b = g.IPn.Contains(ni)
		} else {
			e = fmt.Errorf("Cannot parse %s as IP", ip)
		}
	}
	return
}
