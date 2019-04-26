package pmproxy

import (
	"github.com/lamg/clock"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"testing"
	"time"
)

func TestPersist(t *testing.T) {
	tmc := "2091-04-01T00:00:00-04:00"
	tm, e := time.Parse(time.RFC3339, tmc)
	require.NoError(t, e)
	cm := NewConsMap(tm, time.Second,
		map[string]uint64{"coco": 0, "pepe": 1},
		&clock.TClock{Intv: time.Second, Time: tm})
	rd := cm.Persist()
	bs, e := ioutil.ReadAll(rd)
	require.NoError(t, e)
	require.Equal(t, `{
	"resetTime": 1000000000,
	"lastReset": "`+tmc+`",
	"userCons": {
	"coco": 0,
	"pepe": 1
	}
	}
`, string(bs))
}
