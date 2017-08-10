package main

import (
	"time"
)

type IProxy interface {
	Login(user Name, addr IP, pass string) (u *Account, e error)
	Logout(user Name, pass string) (e error)
	CanReq(user Name, addr IP) (b bool)
	// user: Username
	// addr: Client address
	// meth: HTTP method
	// uri: Accessed URI
	// proto: HTTP version
	// sc: Response status code
	// sz: Response size
	// dt: Response date-time
	LogRes(user Name, addr IP, meth, uri, proto string,
		sc int, sz uint64, dt time.Time) (e error)
}

type (
	IP    string
	Quota uint64
	Name  string

	Account struct {
		User     Name
		Consumed Quota
		Total    Quota
	}
)
