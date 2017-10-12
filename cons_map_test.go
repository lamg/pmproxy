package pmproxy

import (
	"encoding/json"
	"fmt"
	"github.com/lamg/wfact"
	"github.com/stretchr/testify/require"
	"strings"
	"testing"
	"time"
)

func TestConsMap(t *testing.T) {
	dw := wfact.NewDWF()
	cm, e := NewCMFromR(strings.NewReader(cons),
		NewPersister(dw, time.Now(), time.Millisecond))
	require.True(t, e == nil)
	v, ok := cm.Load(coco.User)
	require.True(t, ok)
	require.True(t, v == 8192)
	cm.Reset()
	v, ok = cm.Load(coco.User)
	require.True(t, ok)
	require.True(t, v == 0)
	time.Sleep(time.Millisecond)
	cm.Store(pepe.User, 1)
	om := new(OMap)
	ec := json.Unmarshal(dw.Content(), om)
	require.NoError(t, ec)
	fmt.Printf("%v\n", om.UserCons)
	v, ok = om.UserCons[coco.User]
	require.True(t, ok)
	require.True(t, v == 0)
	v, ok = om.UserCons[pepe.User]
	require.True(t, ok)
	require.True(t, v == 1)
}
