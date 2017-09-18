package pmproxy

import (
	. "github.com/lamg/ldaputil"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

var (
	adAddr  = os.Getenv("AD")
	adSuff  = os.Getenv("AD_SUFF")
	adBDN   = os.Getenv("AD_BDN")
	adAdmG  = os.Getenv("AD_ADMG")
	uprUser = os.Getenv("UPR_USER")
	uprPass = os.Getenv("UPR_PASS")
)

func TestUserInfo(t *testing.T) {
	var ok bool
	va := []string{adAddr, adSuff, adBDN, adAdmG, uprUser, uprPass}
	var i int
	ok, i = true, 0
	for ok && i != len(va) {
		ok = va[i] != ""
		if ok {
			i = i + 1
		}
	}
	require.True(t, ok, "va[%d] = \"\"", i)
	ld, e := NewLdap(adAddr, adSuff, adBDN)
	require.True(t, e == nil || e.Code == ErrorNetwork)
	if e != nil && e.Code == ErrorNetwork {
		t.Log("No network connection")
	} else {
		// TODO use actual groups in AD
		udb := NewLDB(ld, adAdmG)
		u, e := udb.Login(uprUser, uprPass)
		require.True(t, e == nil && len(u.UserName) > 0 &&
			len(u.Name) > 0 && len(u.QuotaGroup) > 0,
			"qg: %s", u.QuotaGroup)
	}
}

func TestElementOf(t *testing.T) {
	a, b, c := []string{"a", "b", "c"}, []string{"c"}, []string{"C"}
	aok, i := hasElementOf(a, b)
	require.True(t, aok && i == 1)
	cok, j := hasElementOf(a, c)
	require.True(t, !cok && j == 1)
}
