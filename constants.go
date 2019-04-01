// Copyright © 2017-2019 Luis Ángel Méndez Gort

// This file is part of PMProxy.

// PMProxy is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.

// PMProxy is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Affero General Public
// License for more details.

// You should have received a copy of the GNU Affero General
// Public License along with PMProxy.  If not, see
// <https://www.gnu.org/licenses/>.

package pmproxy

import (
	"os"
)

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
	nameK          = "name"
	quotasK        = "quotas"
	loggerAddrK    = "loggerAddr"
	groupIPMK      = "groupIPM"
	infoK          = "info"
	dwnConsRK      = "dwnConsR"
	userQuotaK     = "userQuota"
	sessionIPMK    = "sessionIPM"
	userDBK        = "userDB"
	adminsK        = "admins"
	srvConfK       = "srvConf"
	connMngK       = "connMng"
	persistPathK   = "persistPath"
	defaultUserDB  = "mapDB"
	user0          = "user0"
	pass0          = "pass0"
	group0         = "group0"
	defaultIPQuota = "quotas"
	defaultQuota   = "600MB"
	defaultIface   = "eth0"
	mainConfigDir  = "/etc/pmproxy"
	homeConfigDir  = ".config/pmproxy"
	dataDir        = ".local/pmproxy"
	configFile     = "conf.toml"
	addrK          = "addr"
	certK          = "cert"
	keyK           = "key"
	defaultSrvCert = "cert.pem"
	defaultSrvKey  = "key.pem"
	defaultHost    = "localhost"
	ifaceConfK     = "apiSrv"
	proxyConfK     = "proxySrv"
	waitUpdateK    = "waitUpdate"
)

type specKT string

var specK = specKT("spec")

// handlers.go
const (
	proxyOrIfaceK = "proxyOrIface"
	fastOrStdK    = "fastOrStd"
	readTimeoutK  = "readTimeout"
	writeTimeoutK = "writeTimeout"
	maxConnIPK    = "maxConnIP"
	maxReqConnK   = "maxReqConn"

	apiAuth       = "/api/auth"
	apiUserStatus = "/api/userStatus"
	apiCheckUser  = "/api/checkUser"
	apiUserInfo   = "/api/userInfo"
	apiCmd        = "/api/cmd"

	defaultUserInfo   = "defaultUserInfo"
	defaultSessionIPM = "sessions"
	defaultDwnConsR   = "downloads"

	authHd         = "authHd"
	apiPref        = "/api"
	loginPref      = "/login"
	loginPrefSlash = "/login/"

	compatible02K    = "compatible02"
	staticFilesPathK = "staticFilesPath"
)

// sessionIPM.go, dwnConsR.go and other managerKFs
const (
	open      = "open"
	renew     = "renew"
	get       = "get"
	set       = "set"
	del       = "del"
	clöse     = "close"
	showAll   = "showAll"
	skip      = "skip"
	check     = "check"
	add       = "add"
	authNameK = "authName"
	userConsK = "userCons"
	show      = "show"
	discover  = "discover"
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

// rules.go
const (
	ipRangeMK         = "ipRangeM"
	regexpK           = "regexp"
	specKS            = "spec"
	rulesK            = "rules"
	resourcesK        = "resources"
	filterSessionIPMs = "filterSessionIPMs"
)

// dwnConsR.go
const (
	lastResetK  = "lastReset"
	resetCycleK = "resetCycle"
)

// groupIPM.go
const (
	userGroupNK = "ipGroupN"
	groupK      = "group"
)

// rangeIPM.go
const (
	cidrK     = "cidr"
	rangeIPMT = "rangeIPM"
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
	paramsK     = "params"
)

func home() (s string) {
	s = os.Getenv("HOME")
	return
}

const (
	loginSecretFile = "login.secret"
)

// dialer.go
const (
	timeoutK   = "timeout"
	dialerName = "dialer"
)

const basicConfText = `
admins = ["user0"]
rules = "sessions ∧ downloads"

[apiSrv]
	addr = ":4443"
	cert = "cert.pem"
	fastOrStd = false
	key = "key.pem"
	readTimeout = "10s"
	writeTimeout = "15s"

[proxySrv]
	addr = ":8080"
	fastOrStd = false
	readTimeout = "30s"
	writeTimeout = "40s"

[[userDB]]
	adOrMap = false
	name = "mapDB"
	[userDB.quotaMap]
		group0 = "600MB"
	[userDB.params]
		[userDB.params.groups]
			user0 = ["group0"]
		[userDB.params.userPass]
			user0 = "pass0"

[[sessionIPM]]
	authName = "mapDB"
	name = "sessions"

[[dwnConsR]]
	name = "downloads"
	userQuota = "mapDB"
	lastReset = "2019-03-04T12:58:32-05:00"
	resetCycle = "24h0m0s"

[[spec]]
	name = "main"
	iface = "eth0"
	consRs = "downloads"
`
