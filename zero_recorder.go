package pmproxy

import (
	"encoding/json"
	"io"
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

func (d *dZP) Record(l *Log) {
	d.ra = d.ra + 1
}

func (d *dZP) PersistDone(n int) (b bool) {
	b = d.pa == n
	return
}

// Quota recorder
type QuotaRec struct {
	rqc map[Name]uint64
	enc *json.Encoder
}

func (q *QuotaRec) Init(rqc map[Name]uint64, w io.Writer) {
	q.enc, q.rqc = json.NewEncoder(w), rqc
}

func (q *QuotaRec) SetZero() {
	q.enc.Encode(q.rqc)
}

func (q *QuotaRec) Record(l *Log) {
	q.rqc[l.User] = q.rqc[l.User] + l.Cons
}

// Quota reseter
type QuotaRst struct {
	rqc map[Name]uint64
}

func (q *QuotaRst) Init(rqc map[Name]uint64) {
	q.rqc = rqc
}

func (q *QuotaRst) SetZero() {
	for k, _ := range q.rqc {
		q.rqc[k] = 0
	}
}

func (q *QuotaRst) Record(l *Log) {
}

// Log recorder
type RLog struct {
	wr WriterFct
	w  io.Writer
	e  error
}

func (rl *RLog) Init(wr WriterFct) {
	rl.wr = wr
	rl.w, rl.e = rl.wr.Current(), rl.wr.Err()
}

func (rl *RLog) SetZero() {
	rl.wr.NextWriter()
	rl.w, rl.e = rl.wr.Current(), rl.wr.Err()
}

func (rl *RLog) Record(l *Log) {
	//TODO log format
	_, rl.e = rl.w.Write([]byte(l.User))
}

func (rl *RLog) Err() (e error) {
	e = rl.e
	return
}
