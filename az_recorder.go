package pmproxy

import (
	"time"
)

type AZRec struct {
	zTime time.Time
	intv  time.Duration
	zp    ZRecorder
}

func (az *AZRec) Init(zTime time.Time, intv time.Duration,
	zp ZRecorder) {
	az.zTime, az.intv, az.zp = zTime, intv, zp
}

func (az *AZRec) Record(x *Log) {
	var ta time.Duration
	ta = az.timesAfterZeroTime()
	if ta >= 1 {
		az.zTime = az.zTime.Add(az.intv * ta)
		az.zp.SetZero()
	}
	az.zp.Record(x)
}

func (az *AZRec) timesAfterZeroTime() (ta time.Duration) {
	var nw time.Time
	nw = time.Now()
	// { nw - az.zTime < 290 years (by time.Duration's doc.)}
	var cintv time.Duration
	cintv = nw.Sub(az.zTime)
	// { cintv: interval between now and the last}
	ta = cintv / az.intv
	return
}
