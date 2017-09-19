package main

import (
	"crypto/rsa"
	"flag"
	"github.com/dgrijalva/jwt-go"
	"github.com/lamg/ldaputil"
	"github.com/lamg/pmproxy"
	"github.com/lamg/wfact"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"
)

// TODO serve PMProxy.ServeHTTP

func main() {
	var addr, adAddr, qtFile, cnFile, accExcFile, certFile, keyFile,
		logFile, suff, bDN, adAdminG string
	flag.StringVar(&addr, "s", ":8080", "Proxy listen address")
	flag.StringVar(&adAddr, "ad", "ad.upr.edu.cu:636", "AD address with TLS listen port")
	flag.StringVar(&qtFile, "q", "quotas.json",
		`JSON dictionary of group names to quotas. These group names
		must match those in users's distinguishedName field in AD`)
	flag.StringVar(&cnFile, "c", "consumption.json", `JSON 
			dictionary of users to consumptions`)
	flag.StringVar(&accExcFile, "a", "accExcp.json", `JSON list
			of AccExcp objects`)
	flag.StringVar(&keyFile, "k", "key.pem",
		"Private RSA key with PEM format file")
	flag.StringVar(&logFile, "l", "access.log", "access.log file name")
	flag.StringVar(&suff, "sf", "", "Suffix for accounts in AD")
	flag.StringVar(&bDN, "b", "", "AD base DN")
	flag.StringVar(&adAdminG, "ag", "", "AD proxy administrators group")
	flag.Parse()

	var tm time.Time
	tm, e := time.Parse(time.RFC3339, "2017-09-16T00:00:00-04:00")
	var f *os.File
	if e == nil {
		f, e = os.Open(qtFile)
	}
	var gq *pmproxy.MapPrs
	if e == nil {
		tr := wfact.NewTruncater(qtFile)
		gq, e = pmproxy.NewMapPrs(f, tr, time.Now(), 5*time.Minute)
	}
	if e == nil {
		f.Close()
	}
	if e == nil {
		f, e = os.Open(cnFile)
	}
	var uc *pmproxy.MapPrs
	if e == nil {
		tr := wfact.NewTruncater(cnFile)
		uc, e = pmproxy.NewMapPrs(f, tr, time.Now(), 5*time.Minute)
	}
	var bs []byte
	if e == nil {
		bs, e = ioutil.ReadFile(keyFile)
	}
	var pkey *rsa.PrivateKey
	if e == nil {
		pkey, e = jwt.ParseRSAPrivateKeyFromPEM(bs)
	}
	var ld *ldaputil.Ldap
	if e == nil {
		ld, e = ldaputil.NewLdap(adAddr, suff, bDN)
	}
	if e == nil {
		f, e = os.Open(accExcFile)
	}
	var accExc []pmproxy.AccExcp
	if e == nil {
		accExc, e = pmproxy.ReadAccExcp(f)
		f.Close()
	}
	var sm *pmproxy.SMng
	if e == nil {
		cry, udb := pmproxy.NewJWTCrypt(pkey), pmproxy.NewLDB(ld, adAdminG)
		sm = pmproxy.NewSMng(udb, cry)
	}
	if e == nil {
		dt := wfact.NewDateArchiver(logFile)
		rl, qa := pmproxy.NewRLog(dt, sm),
			pmproxy.NewQAdm(sm, gq, uc, accExc, tm, 7*24*time.Hour)
		pm := pmproxy.NewPMProxy(qa, rl)
		// TODO serve HTTPS with valid certificate
		e = http.ListenAndServeTLS(addr, certFile, keyFile, pm)
	}
	if e != nil {
		log.Fatal(e.Error())
	}
}
