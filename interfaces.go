package pmproxy

import (
	"crypto/rsa"
	"io"
	"net/http"
	"net/url"
	"sync"
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
type AdminHandler interface {
	Init(QuotaAdmin)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

// Implemented in proxy_handler.go
// This handler is meant to be an HTTP[S] proxy for
// requests made by authenticated users.
// TODO HTTPS proxy
type ProxyHandler interface {
	Init(ReqLim, Recorder)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

// Implemented in quota_admin.go
type QuotaAdmin interface {
	Init(SessionManager, *sync.Map, *sync.Map, []AccRstr)

	//Exposed subset of SessionManager
	Login(cr *Credentials, addr string) (string, error)
	Logout(string) error

	SetQuota(string, *GroupQuota)
	GetQuota(string, *GroupQuota)
	UserCons(string, *User)
	ReqLim
}

// Implemented in session_manager.go by
// SMng
type SessionManager interface {
	Init(UserDB, Crypt)
	Login(cr *Credentials, addr string) (string, error)
	Logout(string) error
	Check(string) (*User, error)
	UserGroup
	IPUser
}

type UserDB interface {
	Authenticator
	UserGroup
}

type IPUser interface {
	UserName(string) string
}

type UserInf interface {
	UserCons(string) uint64
}

type UserGroup interface {
	GetGroup(string) (string, error)
}

// Implemented in crypt.go by
// JWTCrypt
type Crypt interface {
	Init(*rsa.PrivateKey)
	Encrypt(*User) (string, error)
	Decrypt(string) (*User, error)
}

type User struct {
	Name    string `json:"name"`
	IsAdmin bool   `json:"isAdmin"`
	Cons    uint64 `json:"cons"`
}

// Request Limiter
// Implemented in req_lim.go
type ReqLim interface {
	CanReq(string, *url.URL, time.Time) bool
}

// Implemented in auth.go by
// LdapUPR, dAuth
type Authenticator interface {
	Authenticate(user string, pass string) error
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
