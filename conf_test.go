package pmproxy

import (
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
)

func TestLoadConf(t *testing.T) {
	c, e := ParseConf(strings.NewReader(conf))
	require.True(t, e == nil)
	require.True(t, c.Equal(pconf))
}

var pconf = &Conf{
	ProxySrvAddr: ":9080",
	GrpIface:     map[string]string{"UPR-Internet-Full": "eth0"},
	GrpQtPref:    "UPR-Internet-",
	LogBName:     "logs/access.log",
	AccExcp:      "accExcp.json",
	RsDt:         "2017-09-30T00:00:00-04:00",
	Cons:         "consumos.json",
	Quota:        "cuotas.json",
	UISrvAddr:    ":8081",
	AdmGrp:       "_GrupoRedes",
	StPath:       "public",
	CertFl:       "cert.pem",
	KeyFl:        "key.pem",
	ADAddr:       "10.2.24.35:636",
	ADAccSf:      "@upr.edu.cu",
	BDN:          "dc=upr,dc=edu,dc=cu",
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
