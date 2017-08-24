package pmproxy

import (
	"crypto/rsa"
	"io"
	"net/http"
	"net/url"
	"time"
)

// The implementations of the two following interfaces
// can be used by a single net/http.Server since requests
// meant to be processed exclusively by both handlers are
// easily distinguishable. AdminHandler process local
// requests, and ProxyHandler process remote requests.
// This is done in pmproxy.go

// Implemented in admin_handler.go
// This handler is meant to provide authentication, information
// and administration interfaces
// TODO implement routes
type AdminHandler interface {
	Init(QuotaAdmin)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

// Implemented in proxy_handler.go
// This handler is meant to be an HTTP[S] proxy for
// requests made by authenticated users.
// TODO HTTPS proxy
type ProxyHandler interface {
	Init(IPUser, ReqLim, Recorder)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

type (
	IP   string
	Name string
)

// Implemented in quota_admin.go
// TODO WIP
type QuotaAdmin interface {
	Init(SessionManager, UserGroup, UserInf)

	//Exposed subset of SessionManager
	Login(user Name, addr IP, pass string) (string, error)
	Logout(string) error

	SetGroupQuota(string, string, uint64)
	GetGroupQuota(string, string) uint64
	UserGroup
	UserInf
}

// Implemented in session_manager.go by
// SMng
type SessionManager interface {
	Init(Authenticator, Crypt)
	Login(user Name, addr IP, pass string) (string, error)
	Logout(string) error
	Check(string) (Name, error)
	IPUser
}

type IPUser interface {
	UserName(IP) Name
}

type UserInf interface {
	UserCons(Name) uint64
}

type UserGroup interface {
	GetGroup(Name) string
}

// Implemented in crypt.go by
// JWTCrypt
type Crypt interface {
	Init(*rsa.PrivateKey)
	Encrypt(*User) (string, error)
	Decrypt(string) (*User, error)
}

type User struct {
	Name string `json:"name"`
}

// Request Limiter
// Implemented in req_lim.go
// TODO
// WIP
type ReqLim interface {
	CanReq(Name, *url.URL, time.Time) bool
}

// Implemented in auth.go by
// LdapUPR, dAuth
type Authenticator interface {
	Authenticate(user Name, pass string) error
}

// AZRecorder is a context for ZRecorder
// Implemented in az_recorder.go by
// AZRec
type AZRecorder interface {
	Init(zTime time.Time, intv time.Duration, zp ZRecorder)
	Recorder
}

// Implemented in zero_recorder.go by
// dZP, QuotaRec, QuotaRst, RLog
type ZRecorder interface {
	SetZero()
	Recorder
}

type Recorder interface {
	Record(*Log)
}

// Implemented in writer_factory.go by
// dWF, FWrite
type WriterFct interface {
	Current() io.Writer
	NextWriter()
	Err() error
}

// Implemented in
type INameDict interface {
	Get(Name) uint64
	Set(Name, uint64)
}
