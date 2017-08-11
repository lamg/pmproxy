package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"time"
)

type QPrs struct {
	*QMaps
	rw  io.Writer
	lst time.Time
}

type QMaps struct {
	Grp map[Name]Bytes `json:"grp"`
	Usr map[Name]Bytes `json:"usr"`
	Cns map[Name]Bytes `json:"consumption"`
}

func NewQPrs(rw io.ReadWriter) (q *QPrs, e error) {
	var bs []byte
	qm = new(QMaps)
	bs, e = ioutil.ReadAll(rw)
	if e == nil {
		e = json.Unmarshal(bs, q)
	}
	if e != nil {
		qm = &QMaps{
			make(map[Name]Bytes),
			make(map[Name]Bytes),
			make(map[Name]Bytes),
		}
	}
	q = &QPrs{qm, rw, time.Now()}
	return
}

func (q *QPrs) SetGroupQuota(group Name, qt Bytes) {
	q.Grp[group] = qt
	q.persist()
}

func (q *QPrs) GetGroupQuota(group Name) (qt Bytes) {
	qt = q.Grp[group]
	return
}

func (q *QPrs) SetUserQuota(user Name, qt Bytes) {
	q.Usr[Name] = qt
	q.persist()
}

func (q *QPrs) GetUserQuota(user Name) (qt Bytes) {
	qt = q.Usr[user]
	return
}

func (q *QPrs) GetUserConsumption(user Name) (qt Bytes) {
	qt = q.Cns[user]
	return
}

func (q *QPrs) AddUserConsumption(user Name, qt Bytes) {
	var ok bool
	var q Bytes
	q, ok = q.Cns[user]
	if ok {
		q.Cns[user] = q + qt
		q.persist()
	}
}

const (
	// Five minutes in nanoseconds
	fvMin = 300000000000
)

func (q *QPrs) persist() {
	if q.lst.Add(fvMin).Before(time.Now()) {
		// { it has been more of five minutes since
		//   last persist call}
		var bs []byte
		bs, _ = json.Marshal(q.QMaps)
		q.rw.Write(bs)
	}
}
