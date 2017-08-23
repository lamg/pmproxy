package pmproxy

import (
	"bytes"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestQuotaRec(t *testing.T) {
	qr, bf, coco, cns := new(QuotaRec),
		bytes.NewBuffer(make([]byte, 0)), Name("coco"), uint64(1024)

	qr.Init(make(map[Name]uint64), bf)
	qr.Record(&Log{
		Addr:       "0.0.0.0",
		Meth:       "GET",
		Proto:      "HTTP/1.1",
		RespSize:   cns,
		StatusCode: 200,
		Time:       time.Now(),
		URI:        "http://google.com",
		User:       coco,
	})
	qr.SetZero()
	mp, dc := make(map[Name]uint64), json.NewDecoder(bf)
	e := dc.Decode(&mp)
	require.NoError(t, e)
	require.True(t, mp[coco] == cns,
		"mp[coco] = %d bf.Len() = %d", mp[coco], bf.Len())
}

func TestQuotaRst(t *testing.T) {
	qr, rqc, sl := new(QuotaRst), make(map[Name]uint64),
		[]Name{"coco", "pepe", "kiko"}
	for i, j := range sl {
		rqc[j] = 1 << (10 + uint64(i))
	}
	qr.Init(rqc)
	qr.SetZero()
	for _, j := range sl {
		require.True(t, rqc[j] == 0)
	}
}

func TestRLog(t *testing.T) {
	rl, dwf, u0, u1 := new(RLog), new(dWF),
		&Log{
			User: "coco",
		}, &Log{
			User: "pepe",
		}
	dwf.Init()
	rl.Init(dwf)
	rl.Record(u0)
	require.True(t, dwf.Content() == u0.String())
	rl.SetZero()
	rl.Record(u1)
	require.True(t, dwf.Content() == u1.String())
}
