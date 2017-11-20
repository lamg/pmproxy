package pmproxy

import (
	"io"

	"github.com/lamg/errors"
	w "github.com/lamg/wfact"
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

// NewRLog creates a new RLog
func NewRLog(wr w.WriterFct, iu IPUser) (rl *RLog) {
	rl = &RLog{wr: wr, iu: iu, w: wr.Current()}
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
	_, ec := rl.w.Write([]byte(l.String() + "\n"))
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
