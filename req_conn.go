package pmproxy

import (
	"net"
	"net/url"
	"time"
)

type reqConn struct {
	rAddr string
	url   *url.URL
	tm    time.Time
	// content type
	contTpe string
}

// Connector processes connection requests
type Connector struct {
	sm *SMng
	qm *QMng
}

// GetConn does the actual piping
func (n *Connector) GetConn(r *reqConn) (c net.Conn, e error) {
	var uc *usrRC
	uc, e = n.sm.attachUsr(r)
	var qc *usrQC
	if e == nil {
		qc, e = n.qm.attachInc(uc)
	}
	// goes to every resource manager, associates to
	// the request, using a matcher, some resource it
	// manages
	return
}
