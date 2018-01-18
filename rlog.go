package pmproxy

import (
	"fmt"
	"github.com/lamg/errors"
	"os"
)

const (
	// ErrorRecWrt is the error set when calling record
	ErrorRecWrt = iota
)

// RLog records Log structs to an io.Writer
type RLog struct {
	wr *os.File
	e  *errors.Error
	iu IPUser
}

// NewRLog creates a new RLog
func NewRLog(wr *os.File, iu IPUser) (rl *RLog) {
	rl = &RLog{wr: wr, iu: iu}
	rl.setZero()
	return
}

func (rl *RLog) setZero() {
	// rl.wr.NextWriter()
	// rl.w, rl.e = rl.wr.Current(), rl.wr.Err()
}

func (rl *RLog) record(l *Log) {
	u, e := rl.iu.User(l.Addr)
	if e != nil {
		l.User = "-"
	} else {
		l.User = u.UserName
	}
	rl.wr.Write([]byte(fmt.Sprintf("%s %s %s %s\n",
		l.User, l.Time.String(), l.URI, l.Addr)))
	rl.wr.Sync()
}

func (rl *RLog) err() (e *errors.Error) {
	e = rl.e
	return
}
