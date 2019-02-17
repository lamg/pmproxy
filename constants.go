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
	nameK       = "name"
	quotasK     = "quotas"
	rulesK      = "rules"
	loggerAddrK = "loggerAddr"
	groupIPMK   = "groupIPM"
	infoK       = "info"
	dwnConsRK   = "dwnConsR"
	ipQuotaK    = "ipQuota"
	sessionIPMK = "sessionIPM"
	userDBK     = "userDB"
	adminsK     = "admins"
	srvConfK    = "srvConf"
	connMngK    = "connMng"
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
	get     = "get"
	set     = "set"
	del     = "del"
	clöse   = "close"
	showAll = "showAll"
	skip    = "skip"
)

const (
	posK = "pos"
	reqK = "requestMatcher"
)
