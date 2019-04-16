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
	staticFilesDir   = "staticFiles"
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
	rangeIPMK  = "rangeIPM"
	regexpK    = "regexp"
	specKS     = "spec"
	rulesK     = "rules"
	resourcesK = "resources"
	filter     = "filter"
	object     = "object"
)

// dwnConsR.go
const (
	dwnConsRK   = "dwnConsR"
	userQuotaK  = "userQuota"
	lastResetK  = "lastReset"
	resetCycleK = "resetCycle"
)

// groupIPM.go
const (
	userGroupNK = "userGroup"
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

// bwConsR.go
const (
	bwConsRK  = "bwConsR"
	throttleK = "throttle"
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
rules = "campus ∧ sessions ∧ ((day ∧ downWeek) ∨ (night ∧ downNight)) ∧ ((group0M ∧ bandWidth0) ∨ (group1M ∧ bandWidth1))"

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
	[userDB.params]
		[userDB.params.groups]
			user0 = ["group0"]
			user1 = ["group1"]
		[userDB.params.userPass]
			user0 = "pass0"
			user1 = "pass1"

[[sessionIPM]]
	authName = "mapDB"
	name = "sessions"

[[dwnConsR]]
	name = "downWeek"
	userDB = "mapDB"
	lastReset = "2019-04-13T20:00:00-04:00"
	resetCycle = "168h0m0s"
	
	[dwnConsR.quotaMap]
		group0 = "600MB"
		group1 = "1GB"
	
	[dwnConsR.spec]
		proxyURL = "http://proxy.com:8080"
		iface = "enp0s25"

[[dwnConsR]]
	name = "downNight"
	userDB = "mapDB"
	lastReset = "2019-04-13T20:00:00-04:00"
	resetCycle = "24h"
	
	[dwnConsR.quotaMap]
		group0 = "1GB"
		group1 = "2GB"
	
	[dwnConsR.spec]
		iface = "enp0s25"

[[bwConsR]]
	name = "bandWidth0"
	throttle = 0.9

[[bwConsR]]
	name = "bandWidth1"
	throttle = 1

[[groupIPM]]
	name = "group0M"
	userGroup = "mapDB"
	group = "group0"

[[groupIPM]]
	name = "group1M"
	userGroup = "mapDB"
	group = "group1"

[[span]]
	name = "day"
	start = "2019-03-04T08:00:00-05:00"
	active = "12h"
	total = "24h"
	infinite = true

[[span]]
	name = "night"
	start = "2019-03-04T20:00:00-05:00"
	active = "12h"
	total = "24h"
	infinite = true

[[rangeIPM]]
	name = "campus"
	cidr = "127.0.0.1/32"
`

const indexHTML = `
<html>
	<head>
		<title>PMProxy</title>
	</head>
	<body>Hola desde PMProxy</body>
</html>
`
