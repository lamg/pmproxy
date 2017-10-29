package pmproxy

import (
	"crypto/rsa"
	"io"
	"time"

	"github.com/dgrijalva/jwt-go"
	dl "github.com/lamg/dialer"
	"github.com/lamg/errors"
	fs "github.com/lamg/filesystem"
	"github.com/lamg/wfact"
)

// Conf stores data for initializing PMProxy
type Conf struct {
	// ProxySrvAddr host:port to serve the proxy
	ProxySrvAddr string `json:"proxySrvAddr"`
	// GrpIface group-network interface dictionary file path
	GrpIface map[string]string `json:"grpIface"`
	// GrpQtPref quota group prefix in memberOf field in AD
	GrpQtPref string `json:"grpQtPref"`
	// LogBName is the logs base path and name
	LogBName string `json:"logBName"`
	// AccExcp path of the file with AccExcp JSON format
	AccExcp string `json:"accExcp"`
	// RsDt is the last reset date
	RsDt string `json:"rsDt"`
	// Cons path to the file with the user-consumption
	// JSON dictionary
	Cons string `json:"cons"`
	// Quota path to the file with the group-quota
	// JSON dictionary
	Quota string `json:"quota"`
	// AdmSrvAddr host:port to serve the web user interface
	UISrvAddr string `json:"uiSrvAddr"`
	// AdmGrp is the group the administrators of this system
	// belong, which is associated to their user name in the
	// AD
	AdmGrp string `json:"admGrp"`
	// StPath is the path of the directory with static files
	// to be used by the web user interface
	StPath string `json:"stPath"`
	// LoginAddr is the login web interface URL
	LoginAddr string `json:"loginAddr"`
	// CertFl is the cert.pem file path used to start the HTTPS
	// server that serves the web user interface
	CertFl string `json:"certFl"`
	// KeyFl is the key.pem file path used to start the HTTPS
	// server that serves the web user interface
	KeyFl string `json:"keyFl"`
	// ADAddr host:port where the LDAP server is running
	ADAddr string `json:"adAddr"`
	// ADAccSf is the AD account suffix
	ADAccSf string `json:"adAccSf"`
	// BDN base distinguished name in AD
	BDN string `json:"bdn"`
}

// Equal is the equality comparison
func (c *Conf) Equal(v interface{}) (ok bool) {
	var nc *Conf
	nc, ok = v.(*Conf)
	if ok {
		ok = c.AccExcp == nc.AccExcp && c.ADAccSf == nc.ADAccSf &&
			c.ADAddr == nc.ADAddr && c.AdmGrp == nc.AdmGrp &&
			c.BDN == nc.BDN && c.CertFl == nc.CertFl &&
			c.Cons == nc.Cons &&
			c.GrpQtPref == nc.GrpQtPref && c.KeyFl == nc.KeyFl &&
			c.LogBName == nc.LogBName &&
			c.ProxySrvAddr == nc.ProxySrvAddr && c.Quota == nc.Quota &&
			c.RsDt == nc.RsDt && c.StPath == nc.StPath &&
			c.UISrvAddr == nc.UISrvAddr
	}
	if ok {
		for k, v := range c.GrpIface {
			ok = nc.GrpIface[k] == v
			if !ok {
				// linear search in maps forces to use break
				break
			}
		}
	}
	return
}

// ParseConf parses a JSON formatted Conf object
func ParseConf(r io.Reader) (c *Conf, e *errors.Error) {
	c = new(Conf)
	e = Decode(r, c)
	return
}

// ConfPMProxy uses supplied configuration to initialize
// an instance of PMProxy
func ConfPMProxy(c *Conf, dAuth bool,
	fsm fs.FileSystem) (p *PMProxy, lh *LocalHn,
	e *errors.Error) {
	f, ec := fsm.Open(c.Quota)
	e = errors.NewForwardErr(ec)
	// { c.Quota opened as f ≡ e = nil }
	var gq *QuotaMap
	if e == nil {
		gqp := NewPersister(wfact.NewTruncater(c.Quota, fsm),
			time.Now(), 5*time.Minute)
		gq, e = NewQMFromR(f, gqp)
		f.Close()
	}
	if e == nil {
		f, ec = fsm.Open(c.Cons)
	}
	// { c.Cons opened as f ≡ e = nil }
	var uc *ConsMap
	if e == nil {
		ucp := NewPersister(wfact.NewTruncater(c.Cons, fsm),
			time.Now(), 5*time.Minute)
		uc, e = NewCMFromR(f, ucp)
		f.Close()
	}

	var bs []byte
	if e == nil {
		bs, ec = fsm.ReadFile(c.KeyFl)
		e = errors.NewForwardErr(ec)
	}
	var pkey *rsa.PrivateKey
	if e == nil {
		pkey, ec = jwt.ParseRSAPrivateKeyFromPEM(bs)
		e = errors.NewForwardErr(ec)
	}
	if e == nil {
		f, ec = fsm.Open(c.AccExcp)
		e = errors.NewForwardErr(ec)
	}
	var accExc []AccExcp
	if e == nil {
		accExc, e = ReadAccExcp(f)
		f.Close()
	}
	var udb UserDB
	if dAuth {
		udb = NewDAuth()
	} else {
		udb = NewLDB(c.ADAddr, c.ADAccSf, c.BDN, c.AdmGrp,
			c.GrpQtPref)
	}
	if e == nil {
		cry := NewJWTCrypt(pkey)
		sm := NewSMng(udb, cry)
		dt := wfact.NewDateArchiver(c.LogBName, fsm)
		rl, qa := NewRLog(dt, sm), NewQAdm(sm, gq, uc, accExc)
		rmng := NewRRConnMng(dl.NewOSDialer(), qa, rl, c.GrpIface)
		p = NewPMProxy(rmng, c.LoginAddr)
		// TODO serve HTTPS with valid certificate
		lh = NewLocalHn(qa, c.StPath)
	}
	return
}
