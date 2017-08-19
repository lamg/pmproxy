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
type PMAdmin interface {
	Init(UserInf, QuotaAdmin)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

// Implemented in quota_admin.go
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
// TODO add dependency on a persistence interface
type UserInf interface {
	Init(io.Reader, SessionManager)

	//Exposed subset of SessionManager
	Login(user Name, addr IP, pass string) (string, error)
	Logout(user Name, pass string) error

	UserQuota(string) uint64
	UserConsumption(string) uint64
}

// Implemented in session_manager.go
type SessionManager interface {
	Init(Authenticator, Crypt)
	Login(user Name, addr IP, pass string) (string, error)
	Logout(user Name, pass string) error
	Check(string, Name) error
}

// Implemented in crypt.go
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
type RequestHandler interface {
	Init(QuotaUser, RequestLogger)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

// Implemented in …
type QuotaUser interface {
	CanReq(IP, *url.URL) bool
	AddConsumption(IP, uint64)
}

// Implemented in ldap_upr.go
type Authenticator interface {
	Authenticate(user Name, pass string) error
}

type RequestLogger interface {
	Init(io.Writer)
	// addr: Client address
	// meth: HTTP method
	// uri: Accessed URI
	// proto: HTTP version
	// sc: Response status code
	// sz: Response size
	// dt: Response date-time
	LogRes(addr IP, dest, meth, proto string,
		sc int, sz uint64, dt time.Time) (e error)
}
