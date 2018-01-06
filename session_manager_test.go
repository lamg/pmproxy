package pmproxy_test

import (
	"bytes"
	"fmt"
	"net"
	h "net/http"
	ht "net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	pm "github.com/lamg/pmproxy"
	"github.com/stretchr/testify/require"
)

// tARq means test authentication request and response
type tARq struct {
	usr  string
	pass string
	ip   string
	// response body (JWT)
	body string
	// response result (h.StatusOk or not)
	ok bool
}

func TestLogin(t *testing.T) {
	ua, aa, cr, ur :=
		&tAuth{usrAuthM},
		&tAuth{admAuthM},
		testJWTCrypt(),
		&tUsrRec{}
	s := pm.NewSMng(ua, aa, cr, ur)
	// { initialized SMng }
	hs := []struct {
		// user-password
		um map[string]string
		// h.HandlerFunc to send the log in request
		aHn h.HandlerFunc
		// okRq means if the h.HandlerFunc is meant to log in
		// users that can make requests
		okRq bool
	}{
		{usrAuthM, s.SrvUserSession, true},
		{admAuthM, s.SrvAdmSession, false},
	}
	for _, j := range hs {
		t0 := makeTRq(j.um, 0, true)
		// { t0 has valid users and passwords for logging in
		//   using j.aHn }
		mn := make(map[string]string)
		for i := range t0 {
			fk := fmt.Sprintf("%d", i)
			mn[fk] = fk
		}
		t1 := makeTRq(mn, len(j.um), false)
		ts := append(t0, t1...)
		// { ts[i:] has invalid users for loging in using j.aHn}
		testAuthH(t, j.aHn, ts)
		// { tested j.aHn for all login requests in ts }
		if j.okRq {
			// { handler logs in users that can make requests
			//   to the proxy }
			testHandle(t, ts, s, ur)
			// { tested proxy handling requests according the
			// status in ts's IPs (logged or not) }
		}
		// { tested authentication and proxy request handling if
		//   available for the logged user }
	}
}

func testAuthH(t *testing.T, a h.HandlerFunc, ts []*tARq) {
	for i, j := range ts {
		w, r := reqres(t,
			h.MethodPost,
			"",
			fmt.Sprintf(`{"user":"%s","pass":"%s"}`, j.usr, j.pass),
			"",
			j.ip,
		)
		a.ServeHTTP(w, r)
		require.True(t,
			(w.Code == h.StatusOK) == j.ok ||
				(w.Code == h.StatusBadRequest) == j.ok,
			"Failed at %d", i)
		j.body = w.Body.String()
	}
}

type tUsrRec struct {
	cUsr string
}

func (u *tUsrRec) Rec(usr string) {
	u.cUsr = usr
}

func testHandle(t *testing.T, aq []*tARq, s pm.MaybeResp,
	u *tUsrRec) {
	for i, q := range aq {
		w, r := reqres(t, h.MethodGet, "", "", "", q.ip)
		y := s.Resp(w, r)
		require.Equal(t, q.ok, !y, "At %d", i)
		if y {
			require.Equal(t,
				// To be changed when HTML start to be used
				pm.NotOpInSMsg(q.ip),
				w.Body.String(), "At %d", i)
		} else {
			require.Equal(t, q.usr, u.cUsr, "%s != %s at %d",
				q.usr, u.cUsr, i)
		}
	}
}

func TestLogout(t *testing.T) {
	ua, aa, cr :=
		&tAuth{usrAuthM},
		&tAuth{admAuthM},
		testJWTCrypt()
	s := pm.NewSMng(ua, aa, cr, &tUsrRec{})
	// { initialized SMng }
	ts := []struct {
		m  map[string]string
		hn h.HandlerFunc
	}{
		{usrAuthM, s.SrvUserSession},
		{admAuthM, s.SrvAdmSession},
	}
	ips := 0 // ips is the number in the IP's last octet
	for i, j := range ts {
		ta := makeTRq(j.m, ips, true)
		ips = ips + len(j.m)
		// { ips augmented for not overlaping with the next
		//   iteration IPs }
		for k, l := range ta {
			w, r := reqres(t,
				h.MethodPost,
				"",
				fmt.Sprintf(`{"user":"%s","pass":"%s"}`, l.usr, l.pass),
				"",
				l.ip,
			)
			j.hn.ServeHTTP(w, r)
			require.Equal(t, w.Code, h.StatusOK)
			// { logged in l }
			scrt := w.Body.String()
			w, r = reqres(t, h.MethodDelete, "", "", scrt, l.ip)
			j.hn.ServeHTTP(w, r)
			require.Equal(t, h.StatusOK, w.Code, "At %d,%d", i, k)
			// { logged out l }
			w, r = reqres(t, h.MethodDelete, "", "", scrt, l.ip)
			j.hn.ServeHTTP(w, r)
			require.Equal(t, h.StatusBadRequest, w.Code,
				"At %d,%d", i, k)
			rs := pm.NotOpBySMsg(l.usr, l.ip)
			require.Equal(t, rs, w.Body.String())
			// { trying to log out ofter logged out produces an
			//   error message }
		}
	}
}

// makeTRq creates a slice of test authentication requests
// ips is the starting of generated IPs's last octet
func makeTRq(m map[string]string, ips int,
	ok bool) (r []*tARq) {
	// { ips + len(m) < 256 }
	r = make([]*tARq, len(m))
	i := ips
	for k, v := range m {
		ip := make([]byte, 4)
		ip[3] = ip[3] + byte(i)
		r[i-ips] = &tARq{
			usr:  k,
			pass: v,
			ip:   net.IP(ip).String(),
			ok:   ok,
		}
		i = i + 1
	}
	return
}

func TestNotSuppMeth(t *testing.T) {
	ua, aa, cr :=
		&tAuth{usrAuthM},
		&tAuth{admAuthM},
		testJWTCrypt()
	s := pm.NewSMng(ua, aa, cr, new(tUsrRec))
	// { initialized SMng }
	hs := []struct {
		hn h.HandlerFunc
		ns []string
	}{
		{s.SrvUserSession, []string{h.MethodConnect, h.MethodGet}},
		{s.SrvAdmSession, []string{h.MethodConnect, h.MethodPut}},
	}
	for i, j := range hs {
		for k, l := range j.ns {
			w, r := reqres(t, l, "", "", "", "")
			j.hn(w, r)
			rs := pm.NotSuppMeth(l)
			require.Equal(t, rs.Error(), w.Body.String(), "At %d,%d", i, k)
		}
	}
}

func TestAdmGetSessions(t *testing.T) {
	ua, aa, cr :=
		&tAuth{usrAuthM},
		&tAuth{admAuthM},
		testJWTCrypt()
	s := pm.NewSMng(ua, aa, cr, new(tUsrRec))
	// { initialized SMng }
	ta := makeTRq(usrAuthM, 0, true)
	testAuthH(t, s.SrvUserSession, ta)
	// { logged all users in usrAuthM }
	ts := makeTRq(admAuthM, len(usrAuthM), true)
	for i, j := range ts {
		w, r := reqres(t,
			h.MethodPost,
			"",
			fmt.Sprintf(`{"user":"%s","pass":"%s"}`, j.usr, j.pass),
			"",
			j.ip,
		)
		s.SrvAdmSession(w, r)
		require.Equal(t, w.Code, h.StatusOK, "At %d", i)
		scrt := w.Body.String()
		w, r = reqres(t, h.MethodGet, "", "", scrt, j.ip)
		s.SrvAdmSession(w, r)
		require.Equal(t, h.StatusOK, w.Code, "At %d", i)
		mp := make(map[string]string)
		e := pm.Decode(w.Body, &mp)
		require.NoError(t, e, "At %d", i)
		for k, l := range ta {
			require.Equal(t, l.usr, mp[l.ip], "At %d,%d", i, k)
		}
		// { map returned by request has all ip-pairs in ta }

		nli := "1.0.0.0"
		// { "1.0.0.0" is an IP with closed session since
		//   all IPs with opened sessions start with 0
		//	   (due to makeTRq implementation) }
		w, r = reqres(t, h.MethodGet, "", "", scrt, nli)
		s.SrvAdmSession(w, r)
		require.Equal(t, h.StatusBadRequest, w.Code, "At %d", i)
		require.Equal(t, pm.NotOpBySMsg(j.usr, nli),
			w.Body.String(), "At %d", i)
		// { An error returned for a GET request with a valid
		//   user but with wrong IP (nli) }
	}
}

func TestSwappedSessions(t *testing.T) {
	ua, aa, cr, ur :=
		&tAuth{usrAuthM},
		&tAuth{admAuthM},
		testJWTCrypt(),
		new(tUsrRec)
	s := pm.NewSMng(ua, aa, cr, ur)
	// { initialized SMng }
	ta := makeTRq(usrAuthM, 0, true)
	testAuthH(t, s.SrvUserSession, ta)
	tb := makeTRq(usrAuthM, len(usrAuthM), true)
	testAuthH(t, s.SrvUserSession, tb)
	// { logged same users in ta but from different IPs.
	//   This is done for testing the swapped session message
	//   sent to users. That message is useful in case of an
	//   account being stealed. }
	// { len(ta) = len(tb) }
	for i := 0; i != len(ta); i++ {
		w, r := reqres(t, h.MethodGet, "", "", "", ta[i].ip)
		stop := s.Resp(w, r)
		require.True(t, stop, "At %d", i)
		require.Empty(t, ur.cUsr, "At %d", i)
		require.Equal(t, pm.ClsByMsg(tb[i].ip), w.Body.String(),
			"At %d", i)
		// { closed by message received }
		w, r = reqres(t, h.MethodGet, "", "", "", tb[i].ip)
		stop = s.Resp(w, r)
		require.True(t, stop, "At %d", i)
		require.Empty(t, ur.cUsr, "At %d", i)
		require.Equal(t, pm.RcvFrMsg(ta[i].ip), w.Body.String(),
			"At %d", i)
		// { recovered from message received }
	}
}

type XClaims struct {
	Data string `json:"data"`
	jwt.StandardClaims
}

func TestFatalSecurityBreach(t *testing.T) {
	p, e := jwt.ParseRSAPrivateKeyFromPEM([]byte(privKey))
	require.NoError(t, e)
	x := &XClaims{Data: "hola"}
	tk := jwt.NewWithClaims(jwt.GetSigningMethod("RS256"), x)
	var scrt string
	scrt, e = tk.SignedString(p)
	require.NoError(t, e)

	ua, aa, cr, ur :=
		&tAuth{usrAuthM},
		&tAuth{admAuthM},
		testJWTCrypt(),
		new(tUsrRec)
	s := pm.NewSMng(ua, aa, cr, ur)
	// { initialized SMng }

	w, r := reqres(t, h.MethodDelete, "", "", "", "")
	s.SrvUserSession(w, r)
	require.Equal(t, h.StatusBadRequest, w.Code)
	require.Equal(t, pm.MalformedHd, w.Body.String())
	// { malformed header tested }
	w, r = reqres(t, h.MethodDelete, "", "", scrt, "")
	defer func() {
		msg := recover()
		require.Equal(t, pm.NotJWTUser, msg)
	}()
	s.SrvUserSession(w, r)
}

func TestSrvAdmMngS(t *testing.T) {
	ua, aa, cr, ur :=
		&tAuth{usrAuthM},
		&tAuth{admAuthM},
		testJWTCrypt(),
		new(tUsrRec)
	s := pm.NewSMng(ua, aa, cr, ur)
	// { initialized SMng }
	ta := makeTRq(admAuthM, 0, true)
	testAuthH(t, s.SrvAdmSession, ta)
	for i, j := range ta {
		tu := makeTRq(usrAuthM, len(admAuthM), true)
		for k, l := range tu {
			body := fmt.Sprintf(`{"user":"%s","ip":"%s"}`,
				l.usr, l.ip)
			w, r := reqres(t, h.MethodPost, "", body, j.body, j.ip)
			s.SrvAdmMngS(w, r)
			require.Equal(t, h.StatusOK, w.Code, "At %d,%d %s",
				i, k, w.Body.String())
			// { logged in l.usr from l.ip }
			w, r = reqres(t, h.MethodGet, "", "", "", l.ip)
			stop := s.Resp(w, r)
			require.False(t, stop, "At %d,%d", i, k)
			require.Equal(t, l.usr, ur.cUsr)
			// { l.usr can make requests and is returned by <-uc }
			w, r = reqres(t, h.MethodPut, "", body, j.body, j.ip)
			s.SrvAdmMngS(w, r)
			require.Equal(t, h.StatusOK, w.Code, "At %d,%d", i, k)
			// { logged out l.usr from l.ip }
			w, r = reqres(t, h.MethodGet, "", "", "", l.ip)
			stop = s.Resp(w, r)
			require.True(t, stop, "At %d,%d", i, k)
			require.Empty(t, ur.cUsr)
			// { l.usr cannot make requests }
		}
		w, r := reqres(t, h.MethodDelete, "", "", j.body, j.ip)
		s.SrvAdmMngS(w, r)
		require.Equal(t, h.StatusBadRequest, w.Code)
		require.Equal(t, pm.NotSuppMeth(h.MethodDelete).Error(),
			w.Body.String())
		// { not supported method tested }
	}
}

func reqres(t *testing.T, meth, path, body, hd, addr string) (r *ht.ResponseRecorder,
	q *h.Request) {
	var e error
	if body != "" {
		by := bytes.NewBufferString(body)
		q, e = h.NewRequest(meth, path, by)
	} else {
		q, e = h.NewRequest(meth, path, nil)
	}
	q.Host = net.JoinHostPort(q.Host, "443")
	q.RemoteAddr = net.JoinHostPort(addr, "443")
	if hd != "" {
		q.Header.Set(pm.AuthHd, hd)
	}
	r = ht.NewRecorder()
	require.NoError(t, e)
	return
}

func testJWTCrypt() (cr *pm.JWTCrypt) {
	pk, e := jwt.ParseRSAPrivateKeyFromPEM([]byte(privKey))
	if e != nil {
		panic(e.Error())
	}
	cr = pm.NewJWTCrypt(pk)
	return
}

type tAuth struct {
	usrPass map[string]string
}

func (a *tAuth) Authenticate(user, pass string) (e error) {
	p, ok := a.usrPass[user]
	if !ok {
		e = fmt.Errorf("User %s doesn't exists", user)
	} else if p != pass {
		e = fmt.Errorf("Incorrect password for %s", user)
	}
	return
}

var (
	usrAuthM = map[string]string{
		"coco": "s",
		"pepe": "s0",
	}
	admAuthM = map[string]string{
		"adm":  "t",
		"adm0": "t0",
	}
)

const privKey = `-----BEGIN RSA PRIVATE KEY-----
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
