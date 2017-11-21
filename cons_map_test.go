package pmproxy

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lamg/clock"

	"github.com/lamg/wfact"
	"github.com/stretchr/testify/require"
)

const (
	dtPrs = "2017-10-03T14:00:00-04:00"
)

func TestConsMap(t *testing.T) {
	dw := wfact.NewDWF()
	dt, ec := time.Parse(time.RFC3339, dtPrs)
	require.NoError(t, ec)
	tc := &clock.TClock{Intv: time.Second, Time: dt}
	pr := NewPersister(dw, dt, time.Second, tc)
	cm, e := NewCMFromR(strings.NewReader(cons), pr)
	require.True(t, e == nil)
	usr := []struct {
		user string
		cons uint64
	}{
		{coco.User, 8192},
		{pepe.User, 1024},
	}
	for i := 0; i != len(usr); i++ {
		v, ok := cm.Load(usr[i].user)
		require.True(t, ok)
		require.True(t, v == usr[i].cons, "%d != %d", v,
			usr[i].cons)
	}
	cm.fillBuffer()
	pr.persistNow(cm.bf)
	om := new(OMap)
	ec = json.Unmarshal(dw.Content(), om)
	require.NoError(t, ec)
	for i := 0; i != len(usr); i++ {
		ucm, rc := om.UserCons[usr[i].user], usr[i].cons
		require.True(t, rc == ucm, "ucm = %d ≠ %d at i = %d",
			ucm, rc, i)
	}
	cm.Reset()
	for i := 0; i != len(usr); i++ {
		v, ok := cm.Load(usr[i].user)
		require.True(t, ok)
		require.True(t, v == 0)
	}
}
