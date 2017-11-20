package pmproxy

import (
	"bytes"
	"testing"

	dl "github.com/lamg/dialer"
	"github.com/lamg/errors"
	"github.com/stretchr/testify/require"
)

func TestThrottle(t *testing.T) {
	m, c := newRRConnMng(t)
	ts, ec := m.getThrottle(cocoIP + ":4443")
	require.NoError(t, ec)
	ts0, ok := c.GrpThrottle["A"]
	require.True(t, ok)
	require.True(t, ts.Capacity == ts0.Capacity &&
		ts.Interval == ts0.Interval)
}

func newRRConnMng(t *testing.T) (m *RRConnMng, c *Conf) {
	bf := bytes.NewBufferString(conf)
	var e *errors.Error
	c, e = ParseConf(bf)
	require.True(t, e == nil)
	var qa *QAdm
	var rl *RLog
	qa, rl, e = initQARL()
	require.True(t, e == nil)
	m = NewRRConnMng(dl.NewOSDialer(), qa, rl, c.GrpIface,
		c.GrpThrottle)
	qa.login(coco, cocoIP)
	return
}