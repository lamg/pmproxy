package main

import (
	"net/http"
)

type IProxy interface {
	Login(user, pass, addr string) (u *User, e error)
	Logout(addr string) (e error)
	CanReq(user, addr string) (b bool)
	// user: Username
	// addr: Client address
	// meth: HTTP method
	// uri: Accessed URI
	// proto: HTTP version
	// sc: Response status code
	// sz: Response size
	// dt: Response date-time
	LogRes(user, addr, meth, uri, proto string, sc int, sz uint64,
		dt time.Time) (e error)
}

type (
	IP       string
	Quota    uint64
	Name     string
	Consumed uint64

	User struct {
		Name  Name
		Quota Quota
	}
)
