package pmproxy

import (
	"crypto/rsa"
	"io"
	"net/http"
	"net/url"
	"time"
)

type (
	IP   string
	Name string
)

// Implemented in session_handler.go
// TODO
type PMAdmin interface {
	Init(UserInf, QuotaAdmin)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

// Implemented in quota_admin.go
// TODO
type QuotaAdmin interface {
	Init(io.Reader, io.Writer, SessionManager)

	//Exposed subset of SessionManager
	Login(user Name, addr IP, pass string) (string, error)
	Logout(user Name, pass string) error

	SetGroupQuota(string, Name, uint64)
	GetGroupQuota(string, Name) uint64
	SetUserQuota(string, Name, uint64)
	GetUserQuota(string, Name) uint64
}

// Implemented in user_inf.go
// TODO
type UserInf interface {
	Init(io.Reader, SessionManager)

	//Exposed subset of SessionManager
	Login(user Name, addr IP, pass string) (string, error)
	Logout(user Name, pass string) error

	UserQuota(string) uint64
	UserConsumption(string) uint64
}

// Implemented in session_manager.go by
// SMng
type SessionManager interface {
	Init(Authenticator, Crypt)
	Login(user Name, addr IP, pass string) (string, error)
	Logout(user Name, pass string) error
	Check(string, Name) error
	IPUser
}

type IPUser interface {
	UserName(IP) Name
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

// Implemented in req_handler.go
// TODO find out how a proxy works
// TODO update for new interfaces
// WIP
type RequestHandler interface {
	Init(IPUser, ReqLim, Recorder)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

// Request Limiter
// Implemented in req_lim.go
// TODO
// WIP
type ReqLim interface {
	CanReq(Name, *url.URL) bool
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
