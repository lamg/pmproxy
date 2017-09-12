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
	adBDN   = os.Getenv("AD_DBN")
	adAdmG  = os.Getenv("AD_ADMG")
	uprUser = os.Getenv("UPR_USER")
	uprPass = os.Getenv("UPR_PASS")
)

func TestUserInfo(t *testing.T) {
	var ld *Ldap
	var e error
	ld, e = NewLdap(adAddr, adSuff, adBDN)
	require.NoError(t, e)
	var udb *LDB
	udb = NewLDB(ld, adAdmG, []string{adAdmG, "Prof", "Est"})
	var u *User
	u, e = udb.Login(uprUser, uprPass)
	require.True(t, u != nil && e == nil)
}
