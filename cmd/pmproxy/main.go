package main

import (
	"crypto/rsa"
	"flag"
	"github.com/dgrijalva/jwt-go"
	"github.com/lamg/errors"
	"github.com/lamg/pmproxy"
	"github.com/lamg/wfact"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	var addr, adAddr, qtFile, cnFile, accExcFile, certFile,
		keyFile, logFile, suff, bDN, adAdminG, adQGPref,
		admAddr, spath string
	var dAuth bool
	flag.StringVar(&accExcFile, "a", "accExcp.json",
		"JSON list of AccExcp objects")
	flag.StringVar(&adAddr, "ad", "ad.upr.edu.cu:636",
		"AD address with TLS listen port")
	flag.StringVar(&adAdminG, "ag", "",
		"AD proxy administrators group")
	flag.StringVar(&bDN, "b", "", "AD base DN")
	flag.StringVar(&cnFile, "c", "consumption.json",
		"JSON dictionary of users to consumptions")
	flag.StringVar(&certFile, "ce", "cert.pem",
		"Certificate file with PEM format")
	flag.StringVar(&keyFile, "k", "key.pem",
		"Private RSA key with PEM format file")
	flag.StringVar(&logFile, "l", "access.log",
		"access.log file name")
	flag.StringVar(&adQGPref, "p", "",
		"LDAP server quota group prefix")
	flag.StringVar(&qtFile, "q", "quotas.json",
		`JSON dictionary of group names to quotas. These group names
				must match those in users's distinguishedName field in AD`)
	flag.StringVar(&addr, "s", ":8080", "Proxy listen address")
	flag.StringVar(&admAddr, "adm", ":8081",
		"Address to serve administration HTTPS interface")
	flag.StringVar(&suff, "sf", "", "Suffix for accounts in AD")
	flag.BoolVar(&dAuth, "d", false, "Use dummy authentication instad of LDAP")
	flag.StringVar(&spath, "st", ".", "Directory to serve static files")
	flag.Parse()

	var tm time.Time
	tm, ec := time.Parse(time.RFC3339,
		"2017-09-16T00:00:00-04:00")
	e := nerror(ec)
	var f *os.File
	if e == nil {
		f, ec = os.Open(qtFile)
		e = nerror(ec)
	}
	var gq *pmproxy.MapPrs
	if e == nil {
		tr := wfact.NewTruncater(qtFile)
		gq, e = pmproxy.NewMapPrs(f, tr, time.Now(), 5*time.Minute)
	}
	if e == nil {
		f.Close()
		f, ec = os.Open(cnFile)
		e = nerror(ec)
	}
	var uc *pmproxy.MapPrs
	if e == nil {
		tr := wfact.NewTruncater(cnFile)
		uc, e = pmproxy.NewMapPrs(f, tr, time.Now(), 1*time.Minute)
		e = nerror(ec)
	}
	var bs []byte
	if e == nil {
		bs, ec = ioutil.ReadFile(keyFile)
		e = nerror(ec)
	}
	var pkey *rsa.PrivateKey
	if e == nil {
		pkey, ec = jwt.ParseRSAPrivateKeyFromPEM(bs)
		e = nerror(ec)
	}
	if e == nil {
		f, ec = os.Open(accExcFile)
		e = nerror(ec)
	}
	var accExc []pmproxy.AccExcp
	if e == nil {
		accExc, e = pmproxy.ReadAccExcp(f)
		f.Close()
	}
	var udb pmproxy.UserDB
	if dAuth {
		udb = pmproxy.NewDAuth()
	} else {
		udb = pmproxy.NewLDB(adAddr, suff, bDN, adAdminG, adQGPref)
	}
	var sm *pmproxy.SMng
	if e == nil {
		cry := pmproxy.NewJWTCrypt(pkey)
		sm = pmproxy.NewSMng(udb, cry)
		dt := wfact.NewDateArchiver(logFile)
		rl, qa := pmproxy.NewRLog(dt, sm),
			pmproxy.NewQAdm(sm, gq, uc, accExc, tm, 7*24*time.Hour)

		pm := pmproxy.NewPMProxy(qa, rl, new(pmproxy.NetDialer))
		// TODO serve HTTPS with valid certificate
		lh := pmproxy.NewLocalHn(qa, spath)
		go http.ListenAndServeTLS(admAddr, certFile, keyFile,
			lh)
		ec = http.ListenAndServe(addr, pm)
		e = nerror(ec)
	}
	if e != nil {
		log.Fatal(e.Error())
	}
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
