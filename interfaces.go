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
type SessionHandler interface {
	Init(Crypt, SessionManager, QuotaUser, QuotaAdministrator)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

// Implemented in crypt.go
type Crypt interface {
	Init(*rsa.PrivateKey)
	Encrypt(*User) (string, error)
	Decrypt(string) (*User, error)
}

type User struct {
	Name    string `json:"name"`
	IsAdmin bool   `json:"isAdmin"`
}

// Implemented in req_handler.go
// TODO find out how a proxy works
type RequestHandler interface {
	Init(QuotaUser, RequestLogger)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

type RequestLogger interface {
	Init(io.Writer, IPUser)
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

// Implemented in …
type QuotaUser interface {
	Init(IPUser, UserQPrs)
	CanReq(IP, *url.URL) bool
	AddConsumption(IP, uint64)
}

// Implemented in session_manager.go
type SessionManager interface {
	Init(Authenticator)
	Login(user Name, addr IP, pass string) error
	Logout(user Name, addr IP, pass string) error
	IPUser
}

type IPUser interface {
	User(IP) Name
}

// TODO add dependency on a persistence interface
type UserQPrs interface {
	Init(io.Reader, io.Writer)
	UserQuota(Name) uint64
	UserConsumption(Name) uint64
	SetUserConsumption(Name, uint64)
}

// Implemented in ldap_upr.go
// TODO get user?
type Authenticator interface {
	Authenticate(user Name, pass string) error
}

// Implemented in quota_persist.go
type QuotaAdministrator interface {
	SetGroupQuota(group Name, q uint64)
	GetGroupQuota(group Name) uint64
	SetUserQuota(user Name, q uint64)
	GetUserQuota(user Name) uint64
}
