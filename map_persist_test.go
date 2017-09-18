package pmproxy

import (
	"bytes"
	"encoding/json"
	"github.com/lamg/wfact"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestPersist(t *testing.T) {
	bf := bytes.NewBufferString(cons)
	wf := wfact.NewDWF()
	mp, e := NewMapPrs(bf, wf, time.Now(), 10*time.Millisecond)
	require.True(t, e == nil)
	// { mp:*MapPrs that reads its initial map from bf &&
	//      writes each 10 milliseconds its values to the current
	///     writer at wf}
	v, ok := mp.load(coco.User)
	// { v is an uint64 known to exist with key coco.User in cons }
	require.True(t, ok)
	n := uint64(16384)
	require.True(t, v != n)
	// { n is a new uint64 known to be different from v}
	mp.store(coco.User, n)
	// { n is stored at key coco.User in the in-memory map}
	require.True(t, len(wf.Content()) == 0)
	// { since there's been less than 10 milliseconds the map
	//   shouldn't have been persisted and wf.Content is empty }
	time.Sleep(10 * time.Millisecond)
	ok, e = mp.persistIfTime()
	// { mp has been persisted }
	require.True(t, ok)
	require.True(t, e == nil)
	jm := make(map[string]uint64)
	var ec error
	ec = json.Unmarshal(wf.Content(), &jm)
	require.NoError(t, ec)
	var jn uint64
	jn, ok = jm[coco.User]
	require.True(t, ok)
	require.True(t, jn == n)
}

func TestReset(t *testing.T) {
	bf := bytes.NewBufferString(cons)
	wf := wfact.NewDWF()
	mp, e := NewMapPrs(bf, wf, time.Now(), 10*time.Millisecond)
	require.True(t, e == nil)
	// { mp:*MapPrs that reads its initial map from bf &&
	//      writes each 10 milliseconds its values to the current
	///     writer at wf}
	mp.reset()
	mp.rangeF(func(k string, v uint64) (x bool) {
		require.True(t, v == 0)
		x = v == 0
		return
	})
	require.True(t, len(wf.Content()) == 0)
	// { content of wf is still empty since persist duration hasn't
	//     passed }
	time.Sleep(10 * time.Millisecond)
	var ok bool
	ok, e = mp.persistIfTime()
	// { mp has been persisted }
	require.True(t, ok)
	require.True(t, e == nil)
	jm := make(map[string]uint64)
	var ec error
	ec = json.Unmarshal(wf.Content(), &jm)
	require.NoError(t, ec)
	for _, v := range jm {
		require.True(t, v == 0)
	}
	// { persisted data is ok with mp.Reset behaviour }
}

func TestNewTime(t *testing.T) {
	tm := time.Now()
	dr := time.Hour
	time.Sleep(8 * time.Millisecond)
	n := newTime(tm, dr)
	require.True(t, n.Equal(tm))
}
