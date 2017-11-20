package pmproxy

import (
	"testing"

	fs "github.com/lamg/filesystem"
	"github.com/stretchr/testify/require"
)

func TestConfPMProxy(t *testing.T) {
	bfs, cfile := fs.NewBufferFS(), "conf.json"
	initialFiles := []struct {
		name    string
		content string
	}{
		{cfile, conf},
		{"cuotas.json", quota},
		{"consumos.json", cons},
		{"key.pem", pemKey},
		{"accExcp.json", accR},
	}
	for _, j := range initialFiles {
		f, e := bfs.Create(j.name)
		require.NoError(t, e)
		_, e = f.Write([]byte(j.content))
		require.NoError(t, e)
		f.Close()
	}

	f, e := bfs.Open(cfile)
	require.NoError(t, e)
	c, ec := ParseConf(f)
	require.True(t, ec == nil)
	require.True(t, pconf.Equal(c), "%v", c)
	_, _, ec = ConfPMProxy(c, true, bfs)
	require.True(t, ec == nil)
}

var pconf = &Conf{
	ProxySrvAddr: ":9080",
	GrpThrottle: map[string]float64{
		"A": 0.9,
		"B": 0.8,
	},
	GrpIface: map[string]string{
		"UPR-Internet-Full": "eth0",
	},
	GrpQtPref: "UPR-Internet-",
	LogBName:  "logs/access.log",
	AccExcp:   "accExcp.json",
	RsDt:      "2017-09-30T00:00:00-04:00",
	Cons:      "consumos.json",
	Quota:     "cuotas.json",
	UISrvAddr: ":8081",
	AdmGrp:    "_GrupoRedes",
	StPath:    "public",
	LoginAddr: "http://10.2.24.145:4000",
	CertFl:    "cert.pem",
	KeyFl:     "key.pem",
	ADAddr:    "10.2.24.35:636",
	ADAccSf:   "@upr.edu.cu",
	BDN:       "dc=upr,dc=edu,dc=cu",
}

var conf = `
{
	"dataDir":"dir",
	"hostName":"proxy.org",
	"proxySrvAddr": ":9080",
	"grpIface": {"UPR-Internet-Full":"eth0"},
	"grpThrottle":{
		"A": 0.9,
		"B": 0.8
	},
	"grpQtPref":"UPR-Internet-",
	"logBName":"logs/access.log",
	"accExcp":"accExcp.json",
	"rsDt":"2017-09-30T00:00:00-04:00",
	"cons":"consumos.json",
	"quota":"cuotas.json",
	"uiSrvAddr":":8081",
	"admGrp": "_GrupoRedes",
	"stPath":"public",
	"loginAddr":"http://10.2.24.145:4000",
	"certFl":"cert.pem",
	"keyFl":"key.pem",
	"adAddr":"10.2.24.35:636",
	"adAccSf":"@upr.edu.cu",
	"bdn":"dc=upr,dc=edu,dc=cu"
}
`

var accR = `[
	{"hostRE":"google.com.cu","start":null,"end":null,"consCfc":0},
	{"hostRE":"14ymedio.com","start":"1959-01-01T00:00:00-00:00","end":"2030-01-01T00:00:00-00:00","consCfc":1},
 {"hostRE":"facebook.com","daily":true,"start":"2006-01-02T08:00:00-00:00","end":"2006-01-02T14:00:00-00:00","consCfc":1.5}
 ]`

var cons = `{
	 "lastReset":"2017-10-02T14:00:00-04:00",
	 "resetTime":1000000000,
	 "userCons":{
			"coco": 8192,
			"pepe": 1024
	 }
 }`

var quota = `{
	"A": 8192,
	"B": 4096
 }`

var pemKey = `-----BEGIN RSA PRIVATE KEY-----
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
