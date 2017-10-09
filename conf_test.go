package pmproxy

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestConf(t *testing.T) {
	c := new(Conf)
	e := Decode(strings.NewReader(conf), c)
	require.True(t, e == nil)
	require.True(t, c.ProxySrvAddr == ":9080")
	require.True(t, c.GrpIface["UPR-Internet-Full"] == "eth0")
	require.True(t, c.GrpQtPref == "UPR-Internet-")
	require.True(t, c.LogBName == "logs/access.log")
	require.True(t, c.AccExcp == "accExcp.json")
	require.True(t, c.RsDt == "2017-09-30T00:00:00-04:00")
	require.True(t, c.Cons == "consumos.json")
	require.True(t, c.Quota == "cuotas.json")
	require.True(t, c.UISrvAddr == ":8081")
	require.True(t, c.AdmGrp == "_GrupoRedes")
	require.True(t, c.StPath == "public")
	require.True(t, c.KeyFl == "key.pem")
	require.True(t, c.ADAddr == "10.2.24.35:636")
	require.True(t, c.ADAccSf == "@upr.edu.cu")
	require.True(t, c.BDN == "dc=upr,dc=edu,dc=cu")
}

var conf = `
{
	"proxySrvAddr": ":9080",
	"grpIface": {"UPR-Internet-Full":"eth0"},
	"grpQtPref":"UPR-Internet-",
	"logBName":"logs/access.log",
	"accExcp":"accExcp.json",
	"rsDt":"2017-09-30T00:00:00-04:00",
	"cons":"consumos.json",
	"quota":"cuotas.json",
	"uiSrvAddr":":8081",
	"admGrp": "_GrupoRedes",
	"stPath":"public",
	"certFl":"cert.pem",
	"keyFl":"key.pem",
	"adAddr":"10.2.24.35:636",
	"adAccSf":"@upr.edu.cu",
	"bdn":"dc=upr,dc=edu,dc=cu"
}
`
