package pmproxy

import (
	"fmt"
)

type SessionMng struct {
}

func (s *SessionMng) Exec(cmd *AdmCmd) (r string, e error) {
	switch cmd.Cmd {
	case "open":
		r, e = s.open(cmd.Args)
	case "close":
		r, e = s.close(cmd.Args)
	case "show":
		r, e = s.show(cmd.Args)
	default:
		e = NoCmdWithName(cmd.Cmd)
	}
	return
}

func (s *SessionMng) Match(ip string) (b bool) {
	return
}

func NoCmdWithName(cmd string) (e error) {
	e = fmt.Errorf("No command with name %s", cmd)
	return
}

func (s *SessionMng) open(args []string) (r string, e error) {
	return
}

func (s *SessionMng) close(args []string) (r string, e error) {
	return
}

func (s *SessionMng) show(args []string) (r string, e error) {
	return
}
