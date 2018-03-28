package pmproxy

import (
	"bytes"
	"fmt"
	"net"
	h "net/http"
	ht "net/http/httptest"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"
)

// tARq means test authentication request and response
type tsLg struct {
	user   string
	pass   string
	ip     string
	ok     bool
	header string
}

func TestLogin(t *testing.T) {
	logTestUsrs(t, usrAuthM)
}

func logTestUsrs(t *testing.T, um map[string]string) (s *SMng,
	ts []tsLg, ips []string) {
	ips = make([]string, len(um))
	for i := 0; i != len(um); i++ {
		ips[i] = fmt.Sprintf("0.0.0.%d", i)
	}
	ua := &Auth{Um: um}
	s = NewSMng("sm", ua, nil)
	ts = make([]tsLg, len(um))
	i := 0
	for k, v := range usrAuthM {
		ts[i] = tsLg{
			user: k,
			pass: v,
			ip:   ips[i],
			ok:   true,
		}
		body := fmt.Sprintf(`{"user":"%s","pass":"%s"}`, ts[i].user,
			ts[i].pass)
		r, q := reqres(t, h.MethodPost, "", body, "", ts[i].ip)
		s.SrvUserSession(r, q)
		s.SrvUserSession(r, q)
		require.Equal(t, r.Code, h.StatusOK)
		// { logged }
		usr, ok := s.MatchUsr(ts[i].ip)
		require.True(t, ok)
		require.Equal(t, ts[i].user, usr)
		// { check is logged }
		ts[i].header = r.Body.String()
		// { header stored }
		i = i + 1
	}
	return
}

func TestLogout(t *testing.T) {
	s, ts, ips := logTestUsrs(t, usrAuthM)
	for i, j := range ts {
		r, q := reqres(t, h.MethodDelete, "", "", j.header, j.ip)
		s.SrvUserSession(r, q)
		// { logged out }
		_, ok := s.MatchUsr(j.ip)
		require.False(t, ok, "At %d", i)
		// { checked is logged out }
	}
}

func TestNotSuppMeth(t *testing.T) {
	// TODO
}

func TestAdmGetSessions(t *testing.T) {
	s, ts, ips := logTestUsrs(t, usrAuthM)
}

func TestSwappedSessions(t *testing.T) {
	ua, aa, cr, ur :=
		&tAuth{usrAuthM},
		&tAuth{admAuthM},
		testJWTCrypt(),
		new(tUsrRec)
	s := NewSMng(ua, aa, cr, ur)
	// { initialized SMng }
	ta := makeTRq(usrAuthU, usrAuthP, 0, true)
	testAuthH(t, s.SrvUserSession, ta)
	tb := makeTRq(usrAuthU, usrAuthP, len(usrAuthM), true)
	testAuthH(t, s.SrvUserSession, tb)
	// { logged same users in ta but from different IPs.
	//   This is done for testing the swapped session message
	//   sent to users. That message is useful in case of an
	//   account being stealed. }
	// { len(ta) = len(tb) }
	for i := 0; i != len(ta); i++ {
		w, r := reqres(t, h.MethodGet, "", "", "", ta[i].ip)
		s.ServeHTTP(w, r)
		stop := s.V()
		require.True(t, stop, "At %d", i)
		require.Empty(t, ur.cUsr, "At %d", i)
		require.Equal(t, ClsByMsg(tb[i].ip), w.Body.String(),
			"At %d", i)
		// { closed by message received }
		w, r = reqres(t, h.MethodGet, "", "", "", tb[i].ip)
		s.ServeHTTP(w, r)
		stop = s.V()
		require.True(t, stop, "At %d", i)
		require.Empty(t, ur.cUsr, "At %d", i)
		require.Equal(t, RcvFrMsg(ta[i].ip), w.Body.String(),
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
	s := NewSMng(ua, aa, cr, ur)
	// { initialized SMng }

	w, r := reqres(t, h.MethodDelete, "", "", "", "")
	s.SrvUserSession(w, r)
	require.Equal(t, h.StatusBadRequest, w.Code)
	require.Equal(t, MalformedHd, w.Body.String())
	// { malformed header tested }
	w, r = reqres(t, h.MethodDelete, "", "", scrt, "")
	defer func() {
		msg := recover()
		require.Equal(t, NotJWTUser, msg)
	}()
	s.SrvUserSession(w, r)
}

func TestSrvAdmMngS(t *testing.T) {
	ua, aa, cr, ur :=
		&tAuth{usrAuthM},
		&tAuth{admAuthM},
		testJWTCrypt(),
		new(tUsrRec)
	s := NewSMng(ua, aa, cr, ur)
	// { initialized SMng }
	ta := makeTRq(admAuthU, admAuthP, 0, true)
	testAuthH(t, s.SrvAdmSession, ta)
	for i, j := range ta {
		tu := makeTRq(usrAuthU, usrAuthP, len(admAuthM), true)
		for k, l := range tu {
			body := fmt.Sprintf(`{"user":"%s","ip":"%s"}`,
				l.usr, l.ip)
			w, r := reqres(t, h.MethodPost, "", body, j.body, j.ip)
			s.SrvAdmMngS(w, r)
			require.Equal(t, h.StatusOK, w.Code, "At %d,%d %s",
				i, k, w.Body.String())
			// { logged in l.usr from l.ip }
			w, r = reqres(t, h.MethodGet, "", "", "", l.ip)
			s.ServeHTTP(w, r)
			stop := s.V()
			require.False(t, stop, "At %d,%d", i, k)
			require.Equal(t, l.usr, ur.cUsr)
			// { l.usr can make requests and is returned by <-uc }
			w, r = reqres(t, h.MethodPut, "", body, j.body, j.ip)
			s.SrvAdmMngS(w, r)
			require.Equal(t, h.StatusOK, w.Code, "At %d,%d", i, k)
			// { logged out l.usr from l.ip }
			w, r = reqres(t, h.MethodGet, "", "", "", l.ip)
			s.ServeHTTP(w, r)
			stop = s.V()
			require.True(t, stop, "At %d,%d", i, k)
			require.Empty(t, ur.cUsr)
			// { l.usr cannot make requests }
		}
		w, r := reqres(t, h.MethodDelete, "", "", j.body, j.ip)
		s.SrvAdmMngS(w, r)
		require.Equal(t, h.StatusBadRequest, w.Code)
		require.Equal(t, NotSuppMeth(h.MethodDelete).Error(),
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
		q.Header.Set(AuthHd, hd)
	}
	r = ht.NewRecorder()
	require.NoError(t, e)
	return
}

func testJWTCrypt() (cr *JWTCrypt) {
	pk, e := jwt.ParseRSAPrivateKeyFromPEM([]byte(privKey))
	if e != nil {
		panic(e.Error())
	}
	cr = NewJWTCrypt(pk)
	return
}

var (
	usrAuthU = []string{"coco", "pepe"}
	usrAuthP = []string{"s", "s0"}
	admAuthU = []string{"adm", "adm0"}
	admAuthP = []string{"t", "t0"}
	usrAuthM = map[string]string{
		"coco": "s",
		"pepe": "s0",
	}
	admAuthM = map[string]string{
		"adm":  "t",
		"adm0": "t0",
	}
)
