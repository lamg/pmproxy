package pmproxy

import (
	"net"
	h "net/http"
	"time"
)

type DMng struct {
	Name      string `json:"name"`
	Bandwidth *Rate  `json:"bandwidth"`
	currConn  uint64
	connR     *Rate
	Sm        *SMng `json:"sm"`
}

func (d *DMng) NewConnRate() (r *Rate) {
	d.currConn = d.currConn + 1
	if d.connR == nil {
		d.connR = &Rate{
			TimeLapse: time.Millisecond,
		}
	}
	d.connR.Bytes = d.Bandwidth.Bytes / d.currConn
	r = &Rate{
		Bytes:     d.connR.Bytes,
		TimeLapse: d.connR.TimeLapse,
		CurrConn:  &d.currConn,
	}
	return
}

type dInfo struct {
	Bandwidth *Rate  `json:"bandwidth"`
	CurrConn  uint64 `json:"currConn"`
	ConnR     *Rate  `json:"connR"`
}

func (d *DMng) ServeInfo(w h.ResponseWriter, r *h.Request) {
	// sends info about bandwidth, current amount of connections
	// and current connection rate
	// r.Method = h.MethodGet
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if d.Sm.Match(ip) {
		inf := &dInfo{
			Bandwidth: d.Bandwidth,
			CurrConn:  d.currConn,
			ConnR:     d.connR,
		}
		e = Encode(w, inf)
	}
	writeErr(w, e)
}

func (d *DMng) ServeSetBW(w h.ResponseWriter, r *h.Request) {
	// sets bandwidth
	// r.Method = h.MethodPut
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if d.Sm.Match(ip) {
		bw := new(Rate)
		e = Decode(r.Body, bw)
		if e == nil {
			d.Bandwidth = bw
		}
	}
	writeErr(w, e)
}
