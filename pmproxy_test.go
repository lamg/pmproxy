package pmproxy_test

import (
	h "net/http"
	"testing"

	"github.com/stretchr/testify/require"

	pm "github.com/lamg/pmproxy"
)

type tMR struct {
	r   bool
	msg string
}

func (m *tMR) Resp(w h.ResponseWriter, r *h.Request) (y bool) {
	y = m.r
	w.Write([]byte(m.msg))
	return
}

func TestServeHTTP(t *testing.T) {
	amsg := "test message"
	prx := &pm.PMProxy{
		Pr: []pm.MaybeResp{
			&tMR{r: false, msg: ""},
			&tMR{r: true, msg: amsg}},
	}
	w, r := reqres(t, h.MethodGet, "", "", "", "")
	prx.ServeHTTP(w, r)
	require.Equal(t, w.Body.String(), amsg)
}
