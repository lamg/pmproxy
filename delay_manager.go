package pmproxy

import (
	"net"
	h "net/http"
)

type DMng struct {
	bandwidth *Rate
	currConn  uint32
	connR     *Rate
	sm        *SMng
}

func (d *DMng) NewConnRate() (r *Rate) {
	d.currConn = d.currConn + 1
	d.connR.Bytes = d.bandwidth.Bytes / d.currConn
	r = &Rate{
		Bytes:     d.connR.Bytes,
		TimeLapse: d.connR.TimeLapse,
	}
	return
}

type dInfo struct {
	Bandwidth *Rate  `json:"bandwidth"`
	CurrConn  uint32 `json:"currConn"`
	ConnR     *Rate  `json:"connR"`
}

func (d *DMng) ServeHTTP(w h.ResponseWriter, r *h.Request) {
	ip, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil && d.sm.Match(ip) {
		if r.Method == h.MethodGet {
			// sends info about bandwidth, current amount of connections
			// and current connection rate
			inf := &dInfo{
				Bandwidth: d.bandwidth,
				CurrConn:  d.currConn,
				ConnR:     d.connR,
			}
			e = Encode(w, inf)
		} else if r.Method == h.MethodPut {
			// sets bandwidth
			bw := new(Rate)
			e = Decode(r.Body, bw)
			if e == nil {
				d.bandwidth = bw
			}
		} else {
			e = NotSuppMeth(r.Method)
		}
	}
	writeErr(w, e)
}
