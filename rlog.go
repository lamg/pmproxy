package pmproxy

import (
	"github.com/lamg/errors"
	w "github.com/lamg/wfact"
	"io"
)

const (
	// ErrorRecWrt is the error set when calling record
	ErrorRecWrt = iota
)

// RLog records Log structs to an io.Writer
type RLog struct {
	wr w.WriterFct
	w  io.Writer
	e  *errors.Error
	iu IPUser
}

// Init initializes RLog
func (rl *RLog) Init(wr w.WriterFct, iu IPUser) {
	rl.wr, rl.iu = wr, iu
	rl.w = rl.wr.Current()
}

func (rl *RLog) setZero() {
	rl.wr.NextWriter()
	rl.w, rl.e = rl.wr.Current(), rl.wr.Err()
}

func (rl *RLog) record(l *Log) {
	l.User = rl.iu.User(l.Addr).UserName
	var ec error
	_, ec = rl.w.Write([]byte(l.String() + "\n"))
	if ec != nil {
		rl.e = &errors.Error{
			Code: ErrorRecWrt,
			Err:  ec,
		}
	}
}

func (rl *RLog) err() (e *errors.Error) {
	e = rl.e
	return
}
