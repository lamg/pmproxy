package pmproxy

import (
	"encoding/json"
	"github.com/lamg/wfact"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestConsMap(t *testing.T) {
	dw := wfact.NewDWF()
	pr := NewPersister(dw, time.Now(), time.Millisecond)
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
		require.True(t, v == usr[i].cons)
	}
	cm.fillBuffer()
	pr.persistNow(cm.bf)
	om := new(OMap)
	ec := json.Unmarshal(dw.Content(), om)
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
