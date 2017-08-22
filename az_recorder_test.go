package pmproxy

import (
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestAZPrs(t *testing.T) {
	var zp *dZP
	zp = new(dZP)
	zp.Init()
	var az AZRecorder
	az = new(AZRec)
	var dr time.Duration
	dr = 2 * time.Second
	az.Init(time.Now(), dr, zp)
	var n int
	var l *Log
	n, l = 5, new(Log)
	for i := 0; i != n; i++ {
		az.Record(l)
	}
	time.Sleep(dr)
	az.Record(l)
	require.True(t, zp.PersistDone(n))
}
