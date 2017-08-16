package main

import (
	"time"
)

type (
	IP    string
	Bytes uint64
	Name  string
)

type ProxyUser interface {
	SessionManager
	QuotaUser
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

type QuotaUser interface {
	GetUserQuota(Name) Bytes
	GetUserConsumption(Name) Bytes
	SetUserConsumption(Name, Bytes)
}

type SessionManager interface {
	Login(user Name, addr IP, pass string) error
	Logout(user Name, addr IP, pass string) error
	Logged(user Name) bool
}

type Authenticator interface {
	Authenticate(user Name, pass string) error
}

type ProxyAdministrator interface {
	SessionManager
	QuotaAdministrator
}

type QuotaAdministrator interface {
	SetGroupQuota(group Name, q Bytes)
	GetGroupQuota(group Name) Bytes
	SetUserQuota(user Name, q Bytes)
	GetUserQuota(user Name) Bytes
}
