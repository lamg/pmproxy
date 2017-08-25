// TODO
package pmproxy

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
	"time"
)

func TestQuotaRec(t *testing.T) {
	qr, wf, qmp, coco, cns := new(QuotaRec), NewDWF(),
		new(sync.Map), "coco", uint64(1024)
	qr.Init(qmp, wf)
	qmp.Store(coco, cns)
	qr.SetZero()
	mp, bs := make(map[string]uint64), wf.Content()
	e := json.Unmarshal(bs, &mp)
	require.NoError(t, e)
	require.True(t, mp[coco] == cns,
		"mp[coco] = %d && len(bs) = %d", mp[coco], len(bs))
}

func TestConsRst(t *testing.T) {
	qr, rqc, sl := new(ConsRst), new(sync.Map),
		[]string{"coco", "pepe", "kiko"}
	for i, j := range sl {
		x := 1<<10 + i
		rqc.Store(j, uint64(x))
	}
	qr.Init(rqc)
	qr.SetZero()
	rqc.Range(func(k, v interface{}) (b bool) {
		require.True(t, v == 0)
		b = true
		return
	})
}

func TestRLog(t *testing.T) {
	rl, dwf, u0, u1, iu := new(RLog), new(dWF),
		&Log{
			User: "coco",
		}, &Log{
			User: "pepe",
		},
		new(dIPUser)
	dwf.Init()
	rl.Init(dwf, iu)
	rl.Record(u0)
	cnt, u0s := string(dwf.Content()), u0.String()+"\n"
	require.True(t, cnt == u0s, "%s ≠ %s", cnt, u0s)
	rl.SetZero()
	rl.Record(u1)
	var u1s string
	cnt, u1s = string(dwf.Content()), u1.String()+"\n"
	require.True(t, cnt == u1s, "%s ≠ %s", cnt, u1s)
}

func TestAZPrs(t *testing.T) {
	zp := new(dZP)
	zp.Init()
	az := new(AZr)
	var dr time.Duration
	dr = 2 * time.Second
	az.Init(time.Now(), dr, zp)
	n := 5
	for i := 0; i != n; i++ {
		zp.Add()
	}
	time.Sleep(dr)
	az.SetZero()
	require.True(t, zp.Count() == n, "%d ≠ %d", zp.Count(), n)
}

type dIPUser struct {
}

func (d *dIPUser) UserName(s string) (r string) {
	r = "coco"
	return
}
