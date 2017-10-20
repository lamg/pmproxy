package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"github.com/lamg/errors"
	"github.com/lamg/pmproxy"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	var user, pass, proxyAddr string
	flag.StringVar(&user, "u", "", "User name to login")
	flag.StringVar(&pass, "p", "", "Password to login")
	flag.StringVar(&proxyAddr, "a", "", "Proxy address")
	flag.Parse()

	cr := struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}{user, pass}
	bs, e := json.Marshal(&cr)
	var r *http.Response
	if e == nil {
		http.DefaultClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		r, e = http.Post(proxyAddr+pmproxy.LogX, "text/json",
			bytes.NewReader(bs))
	}
	var lr *pmproxy.LogRs
	if e == nil {
		lr = new(pmproxy.LogRs)
		e = pmproxy.Decode(r.Body, lr)
		r.Body.Close()
	}
	var cons string
	if e == nil {
		cons, e = get(proxyAddr, pmproxy.UserStatus, lr.Scrt)
	}
	if e == nil {
		log.Print(cons)
	}
	if e != nil {
		log.Print(e.Error())
	}
}

func get(addr, path, hd string) (r string, e *errors.Error) {
	var q *http.Request
	if e == nil {
		var ec error
		q, ec = http.NewRequest(http.MethodGet, addr+path, nil)
		e = errors.NewForwardErr(ec)
	}
	var p *http.Response
	if e == nil {
		var ec error
		q.Header.Set(pmproxy.AuthHd, hd)
		p, ec = http.DefaultClient.Do(q)
		e = errors.NewForwardErr(ec)
	}
	var bs []byte
	if e == nil {
		var ec error
		bs, ec = ioutil.ReadAll(p.Body)
		e = errors.NewForwardErr(ec)
	}
	if e == nil {
		r = string(bs)
	}
	return
}
