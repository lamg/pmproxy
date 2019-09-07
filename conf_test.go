package pmproxy

import (
	"github.com/spf13/afero"
	"github.com/stretchr/testify/require"
	"os"
	"path"
	"testing"
)

func TestConf(t *testing.T) {
	home, e := os.UserHomeDir()
	require.NoError(t, e)
	fs := afero.NewMemMapFs()
	e = afero.WriteFile(fs, path.Join(home, confDir, confFile),
		[]byte(cfgExample), 0644)
	require.NoError(t, e)
	p, e := load(fs)
	require.NoError(t, e)
	require.NotNil(t, p.Proxy)
	require.NotNil(t, p.Api)
}

var cfgExample = `
[api]
	httpsCert="cert.pem"
	httpsKey="key.pem"
	webStaticFilesDir="staticFiles"
	persistInterval="5m"
	[api.server]
		readTimeout="30s"
		writeTimeout="20s"
		addr=":4443"
		fastOrStd=true

[proxy]
	dialTimeout="10s"
	[proxy.server]
		readTimeout="30s"
		writeTimeout="20s"
		addr=":8081"
		fastOrStd=true
`
