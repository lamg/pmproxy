package pmproxy

// connMng.go
const (
	proxyTr  = "proxyTransport"
	maxIdleK = "maxIdle"
	idleTK   = "idleT"
	tlsHTK   = "tlsHT"
	expCTK   = "expCT"
)

// conf.go
const (
	nameK        = "name"
	quotasK      = "quotas"
	rulesK       = "rules"
	loggerAddrK  = "loggerAddr"
	groupIPMK    = "groupIPM"
	infoK        = "info"
	dwnConsRK    = "dwnConsR"
	ipQuotaK     = "ipQuota"
	sessionIPMK  = "sessionIPM"
	userDBK      = "userDB"
	adminsK      = "admins"
	srvConfK     = "srvConf"
	connMngK     = "connMng"
	persistPathK = "persistPath"
)

type specKT string

var specK = specKT("spec")

// handlers.go
const (
	proxyOrIfaceK = "proxyOrIface"
	fastOrStdK    = "fastOrStd"
	readTimeoutK  = "readTimeout"
	writeTimeoutK = "writeTimeout"
	addrK         = "addr"
	certK         = "cert"
	keyK          = "key"
	maxConnIPK    = "maxConnIP"
	maxReqConnK   = "maxReqConn"

	apiAuth       = "/api/auth"
	apiUserStatus = "/api/userStatus"
	apiCheckUser  = "/api/checkUser"
	apiUserInfo   = "/api/userInfo"

	defaultUserDBInfo = "defaultUserDBInfo"
	defaultSessionIPM = "sessions"
	defaultDwnConsR   = "downloads"

	authHd         = "authHd"
	apiPref        = "/api"
	loginPref      = "/login"
	loginPrefSlash = "/login/"

	compatible02K    = "compatible0.2"
	staticFilesPathK = "staticFilesPath"
)

// sessionIPM.go, dwnConsR.go and other managerKFs
const (
	open      = "open"
	get       = "get"
	set       = "set"
	del       = "del"
	clöse     = "close"
	showAll   = "showAll"
	skip      = "skip"
	check     = "check"
	add       = "add"
	authNameK = "authName"
)

const (
	posK = "pos"
	reqK = "requestMatcher"
)

const (
	quotaMapK = "quotaMap"
	ifaceK    = "iface"
	proxyURLK = "proxyURL"
	consRK    = "consR"
	unitK     = "unit"
	urlmK     = "urlm"
	spanK     = "span"
	ipmK      = "ipm"
)

// dwnConsR.go
const (
	lastResetK  = "lastReset"
	resetCycleK = "resetCycle"
)

// groupIPM.go
const (
	ipGroupNK = "ipGroupN"
	groupK    = "group"
)

// userDB.go
const (
	adOrMapK    = "adOrMap"
	suffK       = "suff"
	bdnK        = "bdn"
	userK       = "user"
	passK       = "pass"
	userPassK   = "userPass"
	userGroupsK = "groups"
)
