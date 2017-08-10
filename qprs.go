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
	Grp map[Name]Quota `json:"grp"`
	Usr map[Name]Quota `json:"usr"`
}

func NewQPrs(rw io.ReadWriter) (q *QPrs, e error) {
	var bs []byte
	qm = new(QMaps)
	bs, e = ioutil.ReadAll(rw)
	if e == nil {
		e = json.Unmarshal(bs, q)
	}
	if e != nil {
		qm = &QMaps{make(map[Name]Quota), make(map[Name]Quota)}
	}
	q = &QPrs{qm, rw, time.Now()}
	return
}

func (q *QPrs) SetGroupQuota(group Name, qt Quota) {
	q.Grp[group] = qt
	q.persist()
}

func (q *QPrs) GetGroupQuota(group Name) (qt Quota) {
	qt = q.Grp[group]
	return
}

func (q *QPrs) SetUserQuota(user Name, qt Quota) {
	q.Usr[Name] = qt
	q.persist()
}

func (q *QPrs) GetUserQuota(user Name) (qt Quota) {
	qt = q.Usr[user]
	return
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
