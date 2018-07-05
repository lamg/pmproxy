package pmproxy

import (
	"encoding/json"
	"fmt"
	h "net/http"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jinzhu/now"
	"github.com/lamg/clock"
	ld "github.com/lamg/ldaputil"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	yaml "gopkg.in/yaml.v2"
)

func TestStateMng(t *testing.T) {
	stm := afero.NewMemMapFs()
	afr := &afero.Afero{
		Fs: stm,
	}
	fls := []struct {
		name    string
		content string
	}{
		{"conf.yaml", stateFile},
		{"key.pem", keyFile},
		{"cert.pem", certFile},
		{"delay_managers.yaml", delayMsFile},
		{"consumption_managers.yaml", consMsFile},
	}
	for i, j := range fls {
		e := afr.WriteFile(j.name, []byte(j.content), os.ModePerm)
		require.NoError(t, e, "At %d", i)
		fi, e := stm.Stat(j.name)
		require.NoError(t, e)
		require.Equal(t, j.name, fi.Name())
	}
	s, e := NewStateMng("conf.yaml", stm)
	require.NoError(t, e)
	// When the file doesn't exists but apperas in configuration
	// file, it is created. That is the case of
	// resource_determinators.yaml
	_, e = stm.Stat("resource_determinators.yaml")
	require.NoError(t, e)
	require.Equal(t, s.WebAddr, ":443")

	hn := s.WebInterface()
	require.NotNil(t, hn)

	cs, ok := s.Cms["cs"]
	require.True(t, ok)
	require.Equal(t, "cs", cs.Name)

	dm, ok := s.Dms["dm"]
	require.True(t, ok)
	require.Equal(t, "dm", dm.Name)
}

func TestMarshalYAML(t *testing.T) {
	dm := &DMng{
		Bandwidth: &Rate{
			Bytes:     1024,
			TimeLapse: time.Millisecond,
		},
		Name: "dm",
		Sm: &SMng{
			Name: "sm",
		},
	}
	um := &UsrMtch{
		Ul: make([]string, 0),
		Sm: &SMng{
			Name: "sm",
			Usr: &Auth{
				Um: make(map[string]string),
				Ld: ld.NewLdapWithAcc("ad.com", "@ad.com", "dc=ad,dc=com",
					"coco", "pepe"),
			},
		},
	}
	symp := new(sync.Map)
	symp.Store("coco", uint64(64))
	symp.Store("pepe", uint64(128))
	cm := &CMng{
		Cons:       symp,
		Name:       "cm",
		ResetCycle: 168 * time.Hour,
		LastReset:  now.MustParse("2006-01-01"),
		Cl:         new(clock.OSClock),
	}
	clm := &CLMng{
		Limit: 1024,
		Name:  "clm",
	}
	ts := []interface{}{dm, um, cm, clm}
	for i, j := range ts {
		bs, e := yaml.Marshal(j)
		require.NoError(t, e)
		tp := reflect.TypeOf(j).Elem()
		jr := reflect.New(tp).Interface()
		e = yaml.Unmarshal(bs, jr)
		nc, ok := j.(*CMng)
		if ok {
			jc := jr.(*CMng)
			nc.Cons.Range(func(key, value interface{}) (ok0 bool) {
				var v interface{}
				v, ok0 = jc.Cons.Load(key)
				require.Equal(t, value, v)
				return
			})
			require.Equal(t, nc.Name, jc.Name)
			require.Equal(t, nc.ResetCycle, jc.ResetCycle)
			require.Equal(t, nc.LastReset, jc.LastReset)
		} else {
			require.Equal(t, j, jr, "At %d", i)
		}
	}
}

var stateFile = `
webAddr: ":443"
webReadTimeout: 5s
webWriteTimeout: 10s
certFile: cert.pem
keyFile: key.pem
proxyAddr: ":8080"
proxyReadTimeout: 5s
proxyWriteTimeout: 10s

delayMsFile: delay_managers.yaml
consMsFile: consumption_managers.yaml
sessionMsFile: session_managers.yaml
connLimMsFile: connection_limit_managers.yaml
resDetFile: resource_determinators.yaml
`

var delayMsFile = `
dm:
  name: dm
  bandwidth:
    bytes: 1024
    timelapse: 1ms
  sm:
    name: sm
`

var consMsFile = `
cs:
  name: cs
  cons:
    fulano: 128
    mengano: 256
  resetcycle: 168h0m0s
  lastreset: 2006-01-01T00:00:00-04:00
`

var keyFile = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAwaIKZ1NVhEacOSlpwSln2tyie8JVFhBpFQxwDc6Mxrc0f+0H
L5Kj09RoBxFRzW13aVFTT0p2MQ1fqlhZrhOwCFXNjNURiohhIy5Uy4Jhcxl5LOLL
IpVcpksvD9KOHjgTJIH830f5bQTiLatkkNcBuhk340ISdtxgiDzyhXyQsfIxz/m0
rj960N5kvqc9mHrizAEj/saMmDFOTJRAQaQ6NSF76VW2XLC8hImaCYhKMasKoo4b
LliR6UsMjoxzS7wnCmkRf10gvnw5gspMm5UiAwnavMEBdsrUSUWJpS1bQGseNVx6
HHWEbgJAo2RZDCLDmegre7o8mPUuuiBhxPlIMwIDAQABAoIBAG7dKx27vePNVdb4
mh9JaLgLyVAYlQTcAn5Vr7aIA1wnOvzfplSbngdDvwgE55Q5z7vSH2Pvmzo8kQCE
M1yS0yACmHzA5ZkuuocdGNmoXck71YBYnbvATtq7g0eI42vz6Snm7vScTfgYarOB
RUQUhl2Z4MDSbKX3SaHXW3gIOQRYSd7OTuQJnEwVmyFY2cXkbMtREarqAOVHD7ln
PGyguT42FuBZr+jMBPeocvoQlWhAGHaEuZBZZoFQsjYIpGjPLotN5PAlLPPOFaSo
zxZ7hu81goYRmrhQDVsDbKNdrrg4yf3V8P5AuxJ39v8vKIeTsnASMYo4FaLzfWrI
8cGqYIECgYEAySa1q3pYQhp3q7J0T55IqggN4S3dsUy7O2RGrj1v0MfsdWBCjX/J
GloRLIMCLNSOSTwTuRps8YMV7bU7gl+a8vwYGs1JxTFBKZHQtFNiC/td9mXabn7s
40WMXA8G1HiiP4lAsFuhU9xwrSlsQFuylkK/QWHkGnYsNfHuqCOqPfMCgYEA9m6F
4b05A5TCoIVqA3TNOU5hHCH4QZpQ1jRjOeJwc1cQ32KSXO+EXHL71pFXLDzkpHuA
8F+yrifCjAYrDYal57BFrXg6HZAP0X10INv75WotoU37mjiZqFIPgxuW2Cxbs6p6
en7BSEu9hDooSttSoPut/xdEVn+JLBlN5DY+HMECgYEAmaOIdU6AZRUkPK+UaU/D
vqNiPpEy2H58L/P6jJF+e2CIumpoyv1ElG0g2vfBzI4Zk9RgWCzX82wlbqfTqVPu
3RMyMh6E7yoc1Gx8lY9uvyoi7dWEDovB0iHIAHS1ycnOW2sxTsLeKVihc5HFDi87
68tVm9HyUUfbouSEXkbHfIMCgYBjCyC8DbUwf0WKBpUJNpSVB694Ax8oHsGGlh+b
UCsp8EBTx+ZTe+CS15PoNRn4KbEreofkFFJYNJq4dHIxSYC8kdgvVDbnUtNIu0dF
PaUMG5SjVBhfb4gyYmjhpOEHmSxyFX6MZQ2B5Q8Sad1v2J5pHT5dXBiXO0MCelkX
88UbAQKBgQCZ8kg7BA8fjbzIhI2s3n6yombmXI6NUbITI57e+YvPtNXL0p7QnAmd
nCNwnqfECUZ1sp+WBywKaCRIV8w8hzUqUFw5+9/gbZqMQyyrNBtZ90fmGQQ06oQ6
0BZzI/R4mKxOklQwH6qD5WWiXXzmsCDTLcF/cCxRU6/0gMHfAfxsVA==
-----END RSA PRIVATE KEY-----
`

var certFile = `
-----BEGIN CERTIFICATE-----
MIIC/TCCAeWgAwIBAgIRANCf4cVcyPIsRv7+oHPeHMswDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0xODA2MjEyMjIwNDZaFw0xOTA2MjEyMjIw
NDZaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDJJWwfyD0+d+6QVkr7mrBmM81/dlPhJQzjUo8AmFksIv6hqjnsudUz
xe3AipZ4t07Vj/ryiP4A0xBwEqHZSsSVI3psOumw41zQ8cNcJ/IP9uAsBSkELbnN
9OCcpkxtZJlVq+zX3b/H//L1ZVX0tnfV7VZ7C9Zd8Ay+tfbTS/b1V1vyzV8FdtZl
Y23ze08STXEtze9nxIPdr9Y6LZmO9EejcjxbPIvSrwCa42T5n8Fj8c2wZvnmztjq
S1/9x7IKZXDZJvSQryPcVaTWLPvz1trjhFHes/zcVSfe3jAJP+jgHsghLANSBAlo
+lE36Ru+D1CrENZH6FviATuUkQ2y1G7NAgMBAAGjTjBMMA4GA1UdDwEB/wQEAwIC
pDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MBQGA1UdEQQN
MAuCCWxvY2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAUHd+IyLYCwTq47Wnqap+
I6v07B+i0HILQZY2/j8wUwQeEgrGwx3ZIERGFvvBp3PZq9IG7nvHL61Y3ULBmyoV
po/3hqibAFP8DCz3eNOaOqB6hjOTkzaXvh57lkxcLc88eHvuVdhZmKufsUj8cZyI
F0JLW9grmNZw5nn8isowxlPCIPpcgH5GgzoS+tU7xGF1pcuX5UbKg3wB8kmLdl4a
ZnjnTgGXwt9XhW8LAg7x2DAkPnjX5T7pZoMJ+mFB7dFRCBaadRRtWAtU/RttCajf
1tq/AXFt1RWEjsSSEaiXn8KHh2nAjMHz2sM+YEVA/Sz9X4IcqikDJHrrW0FKI336
mg==
-----END CERTIFICATE-----
`

func TestSrvDet(t *testing.T) {
	d := &StateMng{
		MainDet: &SqDet{
			Unit: false,
		},
	}
	ua := &Auth{
		Um: usrAuthM,
	}
	ts := []struct {
		dt  Det
		ind uint32
		add bool
		err bool
	}{
		{
			dt: &SqDet{
				Unit: false,
				RDs: []*ResDet{
					&ResDet{
						Unit: true,
						Cs:   NewCMng("cm"),
					},
				},
			},
			ind: 0,
			add: true,
		},
		{
			dt: &ResDet{
				Um: &UsrMtch{
					Sm: NewSMng("sm", ua, nil),
				},
			},
			ind: 1,
			add: true,
		},
		{
			dt: &SqDet{
				RDs: []*ResDet{
					&ResDet{
						Unit: true,
						Dm: &DMng{
							Name: "dm",
						},
					},
				},
			},
			ind: 1,
			add: true,
		},
		{
			dt: &SqDet{
				RDs: []*ResDet{
					&ResDet{
						Unit: true,
						Dm: &DMng{
							Name: "dm",
						},
					},
				},
			},
			ind: 18,
			add: true,
			err: true,
		},
		{
			dt: &ResDet{
				Um: &UsrMtch{
					Sm: NewSMng("sm", ua, nil),
				},
			},
			ind: 18,
			add: true,
			err: true,
		},
	}
	for i, j := range ts {
		sq0, ok := j.dt.(*SqDet)
		bs, e := json.Marshal(j.dt)
		require.NoError(t, e)

		w, r := reqres(t, h.MethodPost, "/"+Index, string(bs), "",
			"0.0.0.0")
		r = mux.SetURLVars(r, map[string]string{
			Index: fmt.Sprint(j.ind),
		})
		if ok {
			d.SrvAddSqDet(w, r)
		} else {
			d.SrvAddResDet(w, r)
		}
		if !j.err {
			require.Equal(t, h.StatusOK, w.Code, "At %d", i)
			sq := detIndexPreorder(d.MainDet, j.ind)
			if ok {
				v0, v1 := toJSqDet(sq0), toJSqDet(sq.SDs[len(sq.SDs)-1])
				require.Equal(t, v0, v1, "At %d", i)
			} else {
				var dbs []byte
				dbs, e = json.Marshal(sq.RDs[len(sq.RDs)-1])
				require.NoError(t, e)
				require.Equal(t, string(bs), string(dbs), "At %d", i)
			}
		} else {
			require.Equal(t, h.StatusBadRequest, w.Code, "At %d", i)
			require.Equal(t, NoDetFound().Error(), w.Body.String(),
				"At %d", i)
		}
	}

	// DetMng.SrvDet test
	tsd := []struct {
		index string
		err   bool
	}{
		{
			index: "2",
		},
		{
			index: "18",
			err:   true,
		},
	}
	for i, j := range tsd {
		w, r := reqres(t, h.MethodGet, "/"+Index, "", "", "")
		r = mux.SetURLVars(r, map[string]string{
			Index: j.index,
		})
		d.SrvDeterminator(w, r)
		if !j.err {
			require.Equal(t, h.StatusOK, w.Code)
			sq, ok := ts[2].dt.(*SqDet)
			require.True(t, ok)
			v := toJSqDet(sq)
			bs, e := json.Marshal(v)
			require.NoError(t, e)
			require.Equal(t, string(bs), w.Body.String(), "At %d", i)
		} else {
			require.Equal(t, h.StatusBadRequest, w.Code, "At %d", i)
			require.Equal(t, NoDetFound().Error(), w.Body.String(),
				"At %d", i)
		}
	}
}

func TestDetMngAdd(t *testing.T) {
	//TODO
	stm := afero.NewMemMapFs()
	s, e := NewStateMng("conf.yaml", stm)
	require.NoError(t, e)
	ts := []struct {
		tpe string
		val interface{}
		err bool
	}{
		{tpe: CMngType, val: &CMng{Name: "cm"}, err: false},
	}
	for i, j := range ts {
		bs, e := json.Marshal(j.val)
		require.NoError(t, e)
		body := string(bs)
		w, r := reqres(t, h.MethodPost, "", body, "", "0.0.0.0")
		mux.SetURLVars(r, map[string]string{MngType: j.tpe})
		s.SrvAddManager(w, r)
		require.Equal(t, j.err, w.Code == h.StatusOK, "At %d", i)
	}
}
