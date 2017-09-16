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
	var ld *Ldap
	var e error
	ld, e = NewLdap(adAddr, adSuff, adBDN)
	if e == nil {
		var udb *LDB
		udb = NewLDB(ld, adAdmG, []string{adAdmG, "Prof", "Est"})
		var u *User
		u, e = udb.Login(uprUser, uprPass)
		require.True(t, u != nil && e == nil)
	} else {
		t.Log(e.Error())
	}
}
