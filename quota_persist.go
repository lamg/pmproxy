package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"time"
)

type QPrs struct {
	*QMaps
	rw io.Writer
	// lst: five minute counter
	// wk: week counter
	// rd: last week reset
	lst, wk, rd time.Time
}

type QMaps struct {
	Grp map[Name]Bytes `json:"grp"`
	Usr map[Name]Bytes `json:"usr"`
	Cns map[Name]Bytes `json:"consumption"`
}

func NewQPrs(rw io.ReadWriter) (q *QPrs, e error) {
	var bs []byte
	var qm *QMaps
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
	var nw, lss time.Time
	nw = time.Now()
	lss = lastSaturday(nw)
	q = &QPrs{qm, rw, nw, nw, lss}
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
	q.Usr[user] = qt
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

func (q *QPrs) SetUserConsumption(user Name, qt Bytes) {
	q.Cns[user] = qt
	q.persist()
}

const (
	fvMin   = 5 * time.Minute
	oneDay  = 24 * time.Hour
	oneWeek = 7 * oneDay
)

func (q *QPrs) persist() {
	var nw time.Time
	nw = time.Now()
	var fv, ow bool
	fv, ow = q.lst.Add(fvMin).Before(nw), q.rd.Sub(nw) >= oneWeek
	if ow {
		q.rd = lastSaturday(nw)
		for k := range q.Cns {
			q.Cns[k] = 0
		}
		// { account consume is made 0 for every one of them }
	}
	if fv || ow {
		// { it has been more than five minutes since
		//   last persist call ∨ a reset was made for every account}
		q.lst = nw
		var bs []byte
		bs, _ = json.Marshal(q.QMaps)
		q.rw.Write(bs)
	}
}

func lastSaturday(t time.Time) (lss time.Time) {
	// days since Saturday
	var dss time.Weekday
	dss = t.Weekday() + 1
	lss = t.Add(-1 * time.Duration(dss) * oneDay)
	lss = lss.Add(-1 *
		(time.Duration(lss.Hour())*time.Hour +
			time.Duration(lss.Minute())*time.Minute +
			time.Duration(lss.Second())*time.Second +
			time.Duration(lss.Nanosecond())*time.Nanosecond))
	return
}
