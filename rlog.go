package pmproxy

import (
	"fmt"
	"github.com/lamg/errors"
	wf "github.com/lamg/wfact"
	"io"
)

const (
	// ErrorRecWrt is the error set when calling record
	ErrorRecWrt = iota
)

// RLog records Log structs to an io.Writer
type RLog struct {
	wr wf.WriterFct
	w  io.Writer
	e  *errors.Error
	iu IPUser
}

// NewRLog creates a new RLog
func NewRLog(wr wf.WriterFct, iu IPUser) (rl *RLog) {
	rl = &RLog{wr: wr, iu: iu}
	rl.setZero()
	return
}

func (rl *RLog) setZero() {
	rl.wr.NextWriter()
	rl.w, rl.e = rl.wr.Current(), rl.wr.Err()
}

func (rl *RLog) record(l *Log) {
	u, e := rl.iu.User(l.Addr)
	if e != nil {
		l.User = "-"
	} else {
		l.User = u.UserName
	}
	if l.User == "luis.mendez" {
		println(l.String())
	}
	fmt.Fprintln(rl.w, l.String())
}

func (rl *RLog) err() (e *errors.Error) {
	e = rl.e
	return
}
