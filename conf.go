package pmproxy

import (
	"crypto/rsa"
	"encoding/json"
	"github.com/dgrijalva/jwt-go"
	"github.com/lamg/errors"
	"github.com/lamg/wfact"
	"io"
	"io/ioutil"
	"os"
	"time"
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

// ParseConf parses a JSON formatted Conf object
func ParseConf(r io.Reader) (c *Conf, e error) {
	d := json.NewDecoder(r)
	c = new(Conf)
	e = d.Decode(c)
	return
}

// ConfPMProxy uses supplied configuration to initialize
// an instance of PMProxy
func ConfPMProxy(c *Conf, dAuth bool) (p *PMProxy,
	lh *LocalHn, e *errors.Error) {
	f, ec := os.Open(c.Quota)
	e = errors.NewForwardErr(ec)
	// { c.Quota opened as f ≡ e = nil }
	var gq *QuotaMap
	if e == nil {
		gqp := NewPersister(wfact.NewTruncater(c.Quota),
			time.Now(), 5*time.Minute)
		gq, e = NewQMFromR(f, gqp)
		f.Close()
	}
	if e == nil {
		f, ec = os.Open(c.Cons)
		e = errors.NewForwardErr(ec)
	}
	// { c.Cons opened as f ≡ e = nil }
	var uc *ConsMap
	if e == nil {
		ucp := NewPersister(wfact.NewTruncater(c.Cons),
			time.Now(), 5*time.Minute)
		uc, e = NewCMFromR(f, ucp)
		f.Close()
	}

	var bs []byte
	if e == nil {
		bs, ec = ioutil.ReadFile(c.KeyFl)
		e = nerror(ec)
	}
	var pkey *rsa.PrivateKey
	if e == nil {
		pkey, ec = jwt.ParseRSAPrivateKeyFromPEM(bs)
		e = nerror(ec)
	}
	if e == nil {
		f, ec = os.Open(c.AccExcp)
		e = nerror(ec)
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
		dt := wfact.NewDateArchiver(c.LogBName)
		rl, qa := NewRLog(dt, sm), NewQAdm(sm, gq, uc, accExc)
		p = NewPMProxy(qa, rl, c.GrpIface)
		// TODO serve HTTPS with valid certificate
		lh = NewLocalHn(qa, c.StPath)
	}
	return
}

func nerror(e error) (r *errors.Error) {
	if e != nil {
		r = &errors.Error{
			Code: 0,
			Err:  e,
		}
	}
	return
}
