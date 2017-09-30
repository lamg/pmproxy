package pmproxy

import (
	. "github.com/lamg/ldaputil"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

var (
	adAddr   = os.Getenv("AD")
	adSuff   = os.Getenv("AD_SUFF")
	adBDN    = os.Getenv("AD_BDN")
	adAdmG   = os.Getenv("AD_ADMG")
	adQGPref = os.Getenv("AD_QGPREF")
	uprUser  = os.Getenv("UPR_USER")
	uprPass  = os.Getenv("UPR_PASS")
)

func TestUserInfo(t *testing.T) {
	var ok bool
	va := []string{adAddr, adSuff, adBDN, adAdmG, adQGPref,
		uprUser, uprPass}
	var i int
	ok, i = true, 0
	for ok && i != len(va) {
		ok = va[i] != ""
		if ok {
			i = i + 1
		}
	}
	require.True(t, ok, "va[%d] = \"\"", i)
	udb := NewLDB(adAddr, adSuff, adBDN, adAdmG, adQGPref)
	u, e := udb.Login(uprUser, uprPass)
	if e != nil && e.Code == ErrorNetwork {
		t.Log("No network connection")
	} else {
		require.True(t, e == nil && len(u.UserName) > 0 &&
			len(u.Name) > 0 && len(u.QuotaGroup) > 0,
			"qg: %s", u.QuotaGroup)
		t.Log(u.QuotaGroup)
		t.Log(u.IsAdmin)
		// TODO use actual groups in AD
	}
}

func TestElementOf(t *testing.T) {
	a, b, c := []string{"a", "b", "c"}, []string{"c"}, []string{"C"}
	aok, i := hasElementOf(a, b)
	require.True(t, aok && i == 1)
	cok, j := hasElementOf(a, c)
	require.True(t, !cok && j == 1)
}
