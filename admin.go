package main

type Administrator interface {
	SessionManager
	QuotaAdm
}

type QuotaAdministrator interface {
	SetGroupQuota(group Name, group Quota)
	GetGroupQuota(group Name) Quota
	SetUserQuota(user Name, q Quota)
	GetUserQuota(user Name) Quota
}

type SessionManager interface {
	Login(user Name, pass string) error
	Logout(user Name, pass string) error
}

type Authenticator interface {
	Authenticate(user Name, pass string) error
}
