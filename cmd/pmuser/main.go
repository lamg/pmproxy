package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
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
	if e == nil {
		bs, e = ioutil.ReadAll(r.Body)
	}
	var cons string
	if e == nil {
		r.Body.Close()
		cons, e = get(proxyAddr, pmproxy.UserStatus, string(bs))
	}
	if e == nil {
		log.Print(cons)
	}
	if e != nil {
		log.Print(e.Error())
	}
}

func get(addr, path, s string) (r string, e error) {
	var q *http.Request
	q, e = http.NewRequest(http.MethodGet, addr+path, nil)
	var p *http.Response
	if e == nil {
		q.Header.Set(pmproxy.AuthHd, s)
		p, e = http.DefaultClient.Do(q)
	}
	var bs []byte
	if e == nil {
		bs, e = ioutil.ReadAll(p.Body)
	}
	if e == nil {
		r = string(bs)
	}
	return
}
