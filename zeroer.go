package pmproxy

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Quota recorder
type QuotaRec struct {
	rqc *MapPrs
}

func (q *QuotaRec) Init(rqc *MapPrs) {
	q.rqc = rqc
}

func (q *QuotaRec) SetZero() {
	q.rqc.Persist()
}

// Consumption reseter
type ConsRst struct {
	rqc *MapPrs
}

func (q *ConsRst) Init(rqc *MapPrs) {
	q.rqc = rqc
}

func (q *ConsRst) SetZero() {
	q.rqc.mp.Range(func(k string, v uint64) (b bool) {
		q.rqc.mp.Store(k, 0)
		b = true
		return
	})
	q.rqc.Persist()
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

// Tells if time has passed after intv starting at zTime
type Zeroer struct {
	zTime time.Time
	intv  time.Duration
}

func (az *Zeroer) ResetIfZero() (b bool) {
	var nw time.Time
	var ta time.Duration
	nw = time.Now()
	// { nw - az.zTime < 290 years (by time.Duration's doc.)}
	var cintv time.Duration
	cintv = nw.Sub(az.zTime)
	// { cintv: interval between now and the last}
	ta = cintv / az.intv
	b = ta >= 1
	if b {
		az.zTime = az.zTime.Add(az.intv * ta)
	}
	return
}

// Dummy Zeroer implementation
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
