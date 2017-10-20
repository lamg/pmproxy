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
	"strings"
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
	var usr *pmproxy.User
	if e == nil {
		usr = new(pmproxy.User)
		e = pmproxy.Decode(r.Body, usr)
		r.Body.Close()
	}
	var cons string
	if e == nil {
		cons, e = get(proxyAddr, pmproxy.UserStatus, usr)
	}
	if e == nil {
		log.Print(cons)
	}
	if e != nil {
		log.Print(e.Error())
	}
}

func get(addr, path string,
	u *pmproxy.User) (r string, e *errors.Error) {
	var s string
	s, e = u.ToJSON()
	var rd *strings.Reader
	if e == nil {
		rd = strings.NewReader(s)
	}
	var q *http.Request
	if e == nil {
		var ec error
		q, ec = http.NewRequest(http.MethodPost, addr+path, rd)
		e = errors.NewForwardErr(ec)
	}
	var p *http.Response
	if e == nil {
		var ec error
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
