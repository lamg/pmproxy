package pmproxy

import (
	"testing"

	fs "github.com/lamg/filesystem"
	"github.com/stretchr/testify/require"
)

func TestStateMng(t *testing.T) {
	stm := fs.NewBufferFS()
	stm.Bfs = map[string]*fs.BFile{
		"conf.yaml": fs.NewBFile(stateFile),
		"key.pem":   fs.NewBFile(keyFile),
		"cert.pem":  fs.NewBFile(certFile),
	}
	s, e := NewStateMng("conf.yaml", stm)
	require.NoError(t, e)
	require.Equal(t, s.WebAddr, ":443")

	hn := s.WebInterface()
	require.NotNil(t, hn)
}

var stateFile = `
webAddr: ":443"
webReadTimeout: 5s
webWriteTimeout: 10s
certFile: cert.pem
keyFile: key.pem
proxyAddr: ":8080"
proxyReadTimeout: 5s
proxyWriteTimeout: 10s

delayMsFile: delay_managers.json
consMsFile: consumption_managers.json
sessionMsFile: session_managers.json
connLimMsFile: connection_limit_managers.json

resDetFile: resource_determinators.json
`

var keyFile = `
-----BEGIN RSA PRIVATE KEY-----
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

var certFile = `
`
