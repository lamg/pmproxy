package main

import (
	"bytes"
	"encoding/json"
	"flag"
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
		r, e = http.Post(proxyAddr+"/logX", "text/json",
			bytes.NewReader(bs))
	}
	var scrt, qt string
	if e == nil {
		scrt = r.Header.Get("authHd")
	}
	if e == nil {
		qt, e = get(proxyAddr, "/groupQuota", scrt)
	}
	if e == nil {
		log.Print(qt)
		qt, e = get(proxyAddr, "/userCons", scrt)
	}
	if e == nil {
		log.Print(qt)
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
		q.Header.Set("authHd", s)
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
