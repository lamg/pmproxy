package pmproxy

import (
	"bytes"
	"fmt"
	"net"
	h "net/http"
	ht "net/http/httptest"
	"testing"

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
	aa := &Auth{Um: admAuthM}
	sa := NewSMng("adm", aa, nil)
	ua, am := &Auth{Um: usrAuthM}, &UsrMtch{
		Sm: sa,
	}
	s := NewSMng("sm", ua, am)
	logTestUsrs(t, s, usrAuthM, 0)

	// particular cases for improving test coverage
	wusr := "bla"
	_, e := ua.Authenticate(wusr, "co")
	require.Equal(t, WrongPassErr(wusr), e)

	admIP := "0.0.0.1"
	e = s.loginUser(admIP, "eui", "0.0.0.2")
	require.Equal(t, NotAdmin(admIP), e)

	e = checkUser(s.su, wusr, admIP)
	require.Equal(t, NotOpBySMsg(wusr, admIP), e)
}

func logTestUsrs(t *testing.T, s *SMng, um map[string]string,
	st uint32) (ts []tsLg, ips []string) {
	ips = make([]string, len(um))
	for i := uint32(0); i != uint32(len(um)); i++ {
		ips[i] = fmt.Sprintf("0.0.0.%d", st+i)
	}
	hnd, path := s.PrefixHandler().Hnd, "/"+s.Name

	ts = make([]tsLg, len(um))
	i := 0
	for k, v := range um {
		ts[i] = tsLg{
			user: k,
			pass: v,
			ip:   ips[i],
			ok:   true,
		}
		body := fmt.Sprintf(`{"user":"%s","pass":"%s"}`, ts[i].user,
			ts[i].pass)
		r, q := reqres(t, h.MethodPost, path, body, "", ts[i].ip)
		hnd.ServeHTTP(r, q)
		require.Equal(t, r.Code, h.StatusOK, "At %s: %s", k,
			r.Body.String())
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

func logTsLg(t *testing.T, s *SMng, ts []tsLg) {
	hnd, path := s.PrefixHandler().Hnd, "/"+s.Name
	for i, j := range ts {
		body := fmt.Sprintf(`{"user":"%s","pass":"%s"}`, ts[i].user,
			ts[i].pass)
		r, q := reqres(t, h.MethodPost, path, body, "", ts[i].ip)
		hnd.ServeHTTP(r, q)
		require.Equal(t, r.Code, h.StatusOK, "At %s: %s", j.user,
			r.Body.String())
		// { logged }
		usr, ok := s.MatchUsr(ts[i].ip)
		require.True(t, ok)
		require.Equal(t, ts[i].user, usr)
	}
}

func TestLogout(t *testing.T) {
	ua := &Auth{Um: usrAuthM}
	s := NewSMng("sm", ua, nil)
	hnd, path := s.PrefixHandler().Hnd, "/"+s.Name
	ts, _ := logTestUsrs(t, s, usrAuthM, 0)
	for i, j := range ts {
		r, q := reqres(t, h.MethodDelete, path, "", j.header, j.ip)
		hnd.ServeHTTP(r, q)
		// { logged out }
		_, ok := s.MatchUsr(j.ip)
		require.False(t, ok, "At %d", i)
		// { checked is logged out }
	}

	usr, ip := "coco", "0.0.0.0"
	e := s.logout(usr, ip)
	require.Equal(t, NotOpBySMsg(usr, ip), e)
	for i, j := range []string{h.MethodPost, h.MethodPut, h.MethodGet} {
		w, r := reqres(t, j, path, "body", "hd", "0.0.0.0")
		admHnd := s.AdminHandler().Hnd
		admHnd.ServeHTTP(w, r)
		require.Equal(t, h.StatusBadRequest, w.Code)
		require.Equal(t, w.Body.String(), NotAdmHandler().Error(),
			"At %d", i)
	}

}

func TestAdmGetSessions(t *testing.T) {
	aa := &Auth{Um: admAuthM}
	sa := NewSMng("adm", aa, nil)
	ts, _ := logTestUsrs(t, sa, admAuthM, uint32(len(usrAuthM)))

	ua := &Auth{Um: usrAuthM}
	s := NewSMng("sm", ua, &UsrMtch{Sm: sa})
	admHnd, path := s.AdminHandler().Hnd, "/"+s.Name
	logTestUsrs(t, s, usrAuthM, 0)

	for i, j := range ts {
		w, r := reqres(t, h.MethodGet, path, "", j.header, j.ip)
		admHnd.ServeHTTP(w, r)
		require.Equal(t, h.StatusOK, w.Code, "At %d: %s", i,
			w.Body.String())
		m := make(map[string]string)
		e := Decode(w.Body, &m)
		require.NoError(t, e, "At %d", i)
		for k, v := range m {
			usr, ok := s.MatchUsr(k)
			require.True(t, ok)
			require.Equal(t, usr, v)
		}
	}
}

func TestSwappedSessions(t *testing.T) {
	ua := &Auth{Um: usrAuthM}
	s := NewSMng("sm", ua, nil)
	ts, ipa := logTestUsrs(t, s, usrAuthM, 0)
	ipb := make([]string, len(ipa))
	for i := 0; i != len(ts); i++ {
		ts[i].ip = fmt.Sprintf("0.0.0.%d", i+len(ipa))
		ipb[i] = ts[i].ip
	}
	logTsLg(t, s, ts)
	hnd, path := s.PrefixHandler().Hnd, "/"+s.Name
	// { logged same users in ta but from different IPs.
	//   This is done for testing the swapped session message
	//   sent to users. That message is useful in case of an
	//   account being stealed. }
	// { len(ta) = len(tb) }
	for i := 0; i != len(ipa); i++ {
		w, r := reqres(t, h.MethodGet, path, "", "", ipa[i])
		hnd.ServeHTTP(w, r)
		require.Equal(t, ClsByMsg(ipb[i]), w.Body.String(),
			"At %d", i)
		// { closed by message received }
		w, r = reqres(t, h.MethodGet, path, "", "", ipb[i])
		hnd.ServeHTTP(w, r)
		require.Equal(t, RcvFrMsg(ipa[i]), w.Body.String(),
			"At %d", i)
		// { recovered from message received }
	}
}

func TestSrvAdmMngS(t *testing.T) {
	aa := &Auth{Um: admAuthM}
	sa := NewSMng("adm", aa, nil)
	ts, _ := logTestUsrs(t, sa, admAuthM, uint32(len(usrAuthM)))

	ua := &Auth{Um: usrAuthM}
	s := NewSMng("sm", ua, &UsrMtch{Sm: sa})
	admHnd, path := s.AdminHandler().Hnd, "/"+s.Name
	// { initialized SMng }
	for i, j := range ts {
		n := 0
		for k, _ := range usrAuthM {
			ip := fmt.Sprintf("0.0.0.%d", n)
			body := fmt.Sprintf(`{"user":"%s","ip":"%s"}`, k, ip)
			w, r := reqres(t, h.MethodPost, path, body, j.header, j.ip)
			admHnd.ServeHTTP(w, r)
			require.Equal(t, h.StatusOK, w.Code, "At %d,%d %s",
				i, k, w.Body.String())
			// logged in
			w, r = reqres(t, h.MethodPut, path, body, j.header, j.ip)
			admHnd.ServeHTTP(w, r)
			require.Equal(t, h.StatusOK, w.Code, "At %d,%d %s",
				i, k, w.Body.String())
			logged := s.Match(ip)
			require.False(t, logged, "n = %d", n)
			// logged out
			n = n + 1
		}
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
