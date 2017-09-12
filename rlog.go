package pmproxy

import (
	. "github.com/lamg/wfact"
	"io"
)

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
	l.User = rl.iu.User(l.Addr).UserName
	_, rl.e = rl.w.Write([]byte(l.String() + "\n"))
}

func (rl *RLog) Err() (e error) {
	e = rl.e
	return
}
