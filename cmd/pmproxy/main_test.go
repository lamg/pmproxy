package main

import (
	"io/ioutil"
	h "net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDial(t *testing.T) {
	go run("conf.yaml")
	time.Sleep(500 * time.Millisecond)
	tr := &h.Transport{
		Proxy: func(r *h.Request) (u *url.URL, e error) {
			u, e = url.Parse("http://localhost:8081")
			return
		},
	}
	cl := &h.Client{
		Transport: tr,
	}
	r, e := cl.Get("http://bla.com")
	require.NoError(t, e)
	var bs []byte
	bs, e = ioutil.ReadAll(r.Body)
	require.NoError(t, e)
	require.Equal(t, "bla", string(bs))
}
