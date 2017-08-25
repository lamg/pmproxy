package pmproxy

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Dummy ZRecorder implementation
type dZP struct {
	pa, ra int
}

func (d *dZP) Init() {
	d.pa, d.ra = 0, 0
}

func (d *dZP) SetZero() {
	d.pa, d.ra = d.ra, 0
}

func (d *dZP) Add() {
	d.ra = d.ra + 1
}

func (d *dZP) Count() (n int) {
	n = d.pa
	return
}

// Quota recorder
type QuotaRec struct {
	rqc *sync.Map
	wf  WriterFct
}

func (q *QuotaRec) Init(rqc *sync.Map, wf WriterFct) {
	q.rqc, q.wf = rqc, wf
}

func (q *QuotaRec) SetZero() {
	q.wf.NextWriter()
	var e error
	e = q.wf.Err()
	mp := make(map[string]uint64)
	var bs []byte
	if e == nil {
		q.rqc.Range(func(k, v interface{}) (b bool) {
			mp[k.(string)], b = v.(uint64), true
			return
		})
		bs, e = json.Marshal(mp)
	}
	if e == nil {
		_, e = q.wf.Current().Write(bs)
	}
}

// Consumption reseter
type ConsRst struct {
	rqc *sync.Map
}

func (q *ConsRst) Init(rqc *sync.Map) {
	q.rqc = rqc
}

func (q *ConsRst) SetZero() {
	q.rqc.Range(func(k, v interface{}) (b bool) {
		q.rqc.Store(k, 0)
		b = true
		return
	})
}

// Log recorder
type RLog struct {
	wr WriterFct
	w  io.Writer
	e  error
	iu IPUser
}

func (rl *RLog) Init(wr WriterFct, iu IPUser) {
	rl.wr, rl.iu = wr, iu
	rl.w = rl.wr.Current()
}

func (rl *RLog) SetZero() {
	rl.wr.NextWriter()
	rl.w, rl.e = rl.wr.Current(), rl.wr.Err()
}

func (rl *RLog) Record(l *Log) {
	//TODO log format
	l.User = rl.iu.UserName(l.Addr)
	_, rl.e = rl.w.Write([]byte(l.String() + "\n"))
}

func (rl *RLog) Err() (e error) {
	e = rl.e
	return
}

// Automatic Zeroer is a context for Zeroer,
// it calls SetZero after intv duration starting
// at zTime.
type AZr struct {
	zTime time.Time
	intv  time.Duration
	zp    []Zeroer
}

func (az *AZr) Init(zTime time.Time, intv time.Duration,
	z ...Zeroer) {
	az.zTime, az.intv, az.zp = zTime, intv, z
}

func (az *AZr) SetZero() {
	var ta time.Duration
	ta = az.timesAfterZeroTime()
	if ta >= 1 {
		az.zTime = az.zTime.Add(az.intv * ta)
		for _, j := range az.zp {
			j.SetZero()
		}
	}
}

func (az *AZr) timesAfterZeroTime() (ta time.Duration) {
	var nw time.Time
	nw = time.Now()
	// { nw - az.zTime < 290 years (by time.Duration's doc.)}
	var cintv time.Duration
	cintv = nw.Sub(az.zTime)
	// { cintv: interval between now and the last}
	ta = cintv / az.intv
	return
}
