# Manual

## Introduction

An HTTP proxy server is an HTTP server which is used as intermediary between the clients requesting contents from the Word Wide Web, through browsers mainly, and the remote servers that provide it. In that position is possible to control which and how those requests are processed and responded. 

PMProxy is an HTTP proxy server with fine grained control over the connections made through it. It relies on a predicate, supplied in the configuration, which is evaluated (to `true` or `false`) according the parameters of each request. The connection is made if and only if the predicate is evaluated to `true`.

This provides a very flexible model where the predicate depends on the composition, using the standard boolean operators (conjunction, disjunction, negation, implication, consequence, equivalence, difference), of simpler ones designed to match requests by URL, source IP or time it was made.

## Configuration

PMProxy configuration consists in several files at `~/.config/pmproxy`:

- HTTPS certificate file
- HTTPS private key file
- server.toml file
- managers.toml file

Also in that directory the `pmproxy` server could write JSON formatted files with some state that needs to be persisted. The certificate and key files are generated automatically if aren't present. These are configured to serve the API server using HTTPS at `localhost`.

### `server.toml` file

This file contains to objects:

```go
type apiConf struct {
	HTTPSCert         string        `toml:"httpsCert"`
	HTTPSKey          string        `toml:"httpsKey"`
	WebStaticFilesDir string        `toml:"webStaticFilesDir"`
	PersistInterval   time.Duration `toml:"persistInterval"`
	Server            *srvConf      `toml:"server"`
	ExcludedRoutes    []string      `toml:"excludedRoutes"`
}

type proxyConf struct {
	DialTimeout time.Duration `toml:"dialTimeout"`
	Server      *srvConf      `toml:"server"`
}

type srvConf struct {
	ReadTimeout  time.Duration `toml:"readTimeout"`
	WriteTimeout time.Duration `toml:"writeTimeout"`
	Addr         string        `toml:"addr"`
	FastOrStd    bool          `toml:"fastOrStd"`
}
```

The fields with type `time.Duration` are represented by string literals in TOML format, with the suffixs "ns", "ms", "s", "m", "h" (nanosecond, milisecond, second, minute and hour respectively).

- `srvConf`
	+ `ReadTimeout` is the amount of time the server will wait for closing a connection if the client doesn't read data.
	+ `WriteTimeout` is the amount of time the server will wait for closing a connection if the client doesn't write data. Both timeouts are important since not closing stalled connections could lead to consume the amount of them a process can make, limited by the operating system.
	+ `Addr` is the address, including port, the server will listen to requests.
	+ `FastOrStd` indicates whether the implementation for running this server is `github.com/valyala/fasthttp` or `net/http.Server`, `true` for the former and `false` for the latter. 

- `proxyConf`
	+ `DialTimeout` amount of time the proxy will wait before closing a connection with a requested Internet server.
	+ `Server` server configuration described in the `srvConf` object above

- `apiConf`
	+ `HTTPSCert` HTTPS cert file with path relative to the configuration directory
	+ `HTTPSKey` HTTPS key file with path relative to the configuration directory
	+ `WebStaticFilesDir` directory with static files to serve, useful for a web interface.
	+ `PersistInterval` is the amount of time to wait between regular server state persistence operations.
	+ `Server` server configuration described in the `srvConf` object above
	+ `ExcludedRoutes` routes that the server will redirect to "/" instead of trying to serve a file with the requested path.

The `server.toml` file is an object itself:

```go
type pmproxyConf struct {
	Api   *apiConf   `toml:"api"`
	Proxy *proxyConf `toml:"proxy"`
}
```

An example content is (notice the fields have the names in the "toml" tags associated to the object field names described above):

```toml
[api]
	excludedRoutes=["/about"]
	httpsCert="cert.pem"
	httpsKey="key.pem"
	webStaticFilesDir="staticFiles"
	persistInterval="5m"
	[api.server]
		readTimeout="30s"
		writeTimeout="20s"
		addr=":4443"
		fastOrStd=false

[proxy]
	dialTimeout="10s"
	[proxy.server]
		readTimeout="30s"
		writeTimeout="20s"
		addr=":8080"
		fastOrStd=false
```

### `managers.toml` file

This file contains all the configuration for the predicate used for allowing and controlling the connections. It contains an instance of the following object serialized to TOML:

```go
type conf struct {
	JWTExpiration time.Duration    `toml:"jwtExpiration"`
	Admins        []string         `toml:"admins"`
	DwnConsR      []*DwnConsR      `toml:"dwnConsR"`
	AdDB          *adDB            `toml:"adDB"`
	MapDB         *mapDB           `toml:"mapDB"`
	ParentProxy   []*proxyURLMng   `toml:"parentProxy"`
	NetIface      []*proxyIfaceMng `toml:"netIface"`
	RangeIPM      []*rangeIPM      `toml:"rangeIPM"`
	Rules         string           `toml:"rules" default:"true"`
	SessionIPM    []*sessionIPM    `toml:"sessionIPM"`
	SyslogAddr    string           `toml:"syslogAddr"`
	TimeSpan      []*span          `toml:"timeSpan"`
}
```

- `JWTExpiration` is the amount of time until the JSON Web Token, sent to clients opening sessions successfuly, expires.
- `Admins` list of users with privileged access, that managers check in order to perform some operations.
- `SyslogAddr` address of a syslog server or empty for the local machine, which will process the logs generated by the PMProxy instance.

#### `Rules`

This field is a string representing a predicate with the format described in https://github.com/lamg/predicate. The identifiers in it are the name of the objects at `DwnConsR`, `ParentProxy`, `NetIface`, `RangeIPM`, `SessionIPM` and `TimeSpan` fields. When the predicate is evaluated, every time a connection is opened, each object referenced in it by its name provides a `true` or `false` value. In case there isn't a corresponding object for an identifier in the predicate, the latter will be evaluated to an expression depending on that identifier, and the proxy will not allow that connection.

Objects like `DwnConsR`, `ParentProxy` and `NetIface` always evaluate to `true` if the predicate evaluation reaches the identifiers equal to their names. In case the evaluation reaches them, they become associated to the connection for controlling or parameterizing it. 

For example, with `night` and `day` predicates of type `TimeSpan`, matching connections made at night or day respectively, the following predicate will associate different objects of type `DwnConsR` (`down0` or `down1`) to the connection made:

`(night ∧ down0) ∨ (day ∧ down1)`

#### `DownConsR`

It's an abbreviation of "download consumption restrictor". When this object becomes associated to a connection it restricts the amount of data it can read (download from the Internet). When the consumption reaches the limit no further read is allowed. The limit, also called quota, is loaded from the configuration. There it appears associated to a string which is the name of a group of users. Those groups are determined by an object of type `adDB` or `mapDB`. The user is determined by the client IP that made the connection, and a register of IPs associated to users. Adding a key value to that register is the role of the `SessionIPM` object. The accumulated consumptions for each user are reseted periodically.

The object has the following fields: 

```go
type DwnConsR struct {
	Name       string            `toml:"name"`
	UserDBN    string            `toml:"userDBN"`
	ResetCycle time.Duration     `toml:"resetCycle"`
	GroupQuota map[string]string `toml:"groupQuota"`
}
```

- `Name` is the value of the identifier used in the predicate for referencing it when reached by evaluation.
- `UserDBN` is the name of the `adDB` or `mapDB` object providing the mapping from users to groups.
- `ResetCycle` is the amount of time the consumptions for each user are accumulated before setting them to 0 automatically.
- `GroupQuota` is the mapping of groups to quotas.

When `DwnConsR` is initialized it tries to load an object of type `consMap` from the configuration directory, in a file with name `Name`+".json". The `consMap` object is defined:

```go
type consMap struct {
	LastReset    time.Time         `json:"lastReset"`
	Consumptions map[string]uint64 `json:"consumptions"`
}
``` 

- `LastReset` is the date of the last time all consumptions were set to 0, because the difference between the current time and `LastReset` was equal or greater than `ResetCycle`.
- `Consumptions` is a mapping from users to accumulated consumptions in the period of time starting in `LastReset` with `ResetCycle` duration.

In case that file doesn't exists it will be created with the current date as `LastReset` value, and the accumulated user consumptions as `Consumptions` value,  between the time the server was started and the time the first regular persist operation is executed. That time is specified by `apiConf.PersistInterval`. 

#### `SessionIPM`

It's an abbreviation of "session IP matcher", a predicate returning `true` when requests come from an IP previously authorized by the same instance getting the `Match` command. The authorization request is sent through the [API](##api-description). The object is defined:

```go
type sessionIPM struct {
	Name string `toml:"name"`
	Auth string `toml:"auth"`
}
```

- `Name` has the value of the identifier used to reference it from the predicate.
- `Auth` has the name of the `adDB` or `mapDB` instance used to authenticate user credentials.

#### `RangeIPM`

It's an abbreviation of "range IP matcher", a predicate returning `true` when requests come from an IP belonging to the configured range. The object is defined:

```go
type rangeIPM struct {
	Cidr string `toml:"cidr"`
	Name string `toml:"name"`
}
```

- `Cidr` is the IP range specified with [CIDR][0] format
- `Name` is the value used as identifier for referencing it in the predicate

#### `TimeSpan`

Is a predicate. Returns `true` when the request is received between the configured time interval. The object is defined:

```go
type span struct {
	Span *rt.RSpan `toml:"span"`
	Name string    `toml:"name"`
}
```

- `Name` is the value used as identifier for referencing it in the predicate.
- `Span` is an [RSpan][1] object.

#### `NetIface`

Is a predicate and always returns `true`. If the evaluation reaches it, assigns a network interface for making the connection needed for processing the matching request. The object is defined:

```go
type proxyIfaceMng struct {
	Name  string `toml:"name"`
	Iface string `toml:"iface"`
}
```

- `Name` is the value used as identifier for referencing it in the predicate.
- `Iface` is the name of the network interface for making connections needed for processing matching requests.

#### `ParentProxy`

Is a predicate and always returns `true`. If the evaluation reaches it, assigns a parent proxy for making the connection needed for processing the matching request. The object is defined:

```go
type proxyURLMng struct {
	Name     string `toml:"name"`
	ProxyURL string `toml:"proxyURL"`
}
```

- `Name` is the value used as identifier for referencing it in the predicate.
- `ProxyURL` is the URL of the parent proxy for making the connection needed for processing the matching request. It can be an HTTP or SOCKS5 proxy, this must be reflected in the URL scheme.

#### `MapDB`

Is a dependency of `SessionIPM` and `DwnConsR`. To the former provides a means of authenticating credentials, to the latter a, one to many, mapping from users to groups. The object is defined:

```go
type mapDB struct {
	Name      string              `toml:"name"`
	UserPass  map[string]string   `toml:"userPass"`
	UserGroup map[string][]string `toml:"userGroups"`
}
```

- `Name` is the value used by a `SessionIPM` or `DwnConsR` instance for referencing it.
- `UserPass` is an one to one mapping from users to passwords
- `UserGroup` is an one to many mapping from users to groups

#### `AdDB`

Is a dependency of `SessionIPM` and `DwnConsR`. To the former provides a means of authenticating credentials, to the latter a, one to many, mapping from users to groups. However, unlike `MapDB` the authentication and user group mapping is provided by an external server, accessed through the LDAP protocol. The object is defined:

```go
type adDB struct {
	Name string `toml:"name"`
	Addr string `toml:"addr"`
	Suff string `toml:"suff"`
	Bdn  string `toml:"bdn"`
	User string `toml:"user"`
	Pass string `toml:"pass"`
}
```

- `Name` is the value used by a `SessionIPM` or `DwnConsR` instance for referencing it.
- `Addr` is the address of the LDAP server
- `Suff` is the suffix every user name needs for login.
- `Bdn` is the LDAP [BDN][3].
- `User` is the dedicated user for making queries to the LDAP server.
- `Pass` corresponding password for `User`.

#### Example file

```toml
rule = "sessions ∧ ((day ∧ down) ∨ night)"

[[sessionIPM]]
	name = "sessions"
	auth = "ad"

[[dwnConsR]]
	name = "down"
	userDBN = "ad"
	resetCycle = "24h"
	[dwnConsR.groupQuota]
		group0 = "1 GB"

[adDB]
	name = "ad"
	addr = "ldap.org:636"
	suff = "@account.org"
	bdn = "dc=ldap,dc=org"
	user = "ad-user"
	pass = "secret"

[[timeSpan]]
	name = "day"
	[timeSpan.Span]
		start = 2006-01-02-T08:00:00-04:00
		active = 	"12h"
		total = "24h"
		infinite = true

[[timeSpan]]
	name = "night"
	[timeSpan.Span]
		start = 2006-01-02-T20:00:00-04:00
		active = "12h"
		total = "24h"
		infinite = true
```

With the previous configuration users have a quota of 1 Gb during the day, reseted every day. While at nights they connect without quota.

## API description

Using the proxy server requires making queries to the API, which runs as an HTTPS server, processing `POST` requests sent to `/api/cmd`, under the URL configured to identify the server. The endpoint receives a JSON formatted `Cmd` object.

```go
type Cmd struct {
	Cmd        string                 `json:"cmd"`
	User       string                 `json:"user"`
	Manager    string                 `json:"manager"`
	RemoteAddr string                 `json:"remoteAddr"`
	Secret     string                 `json:"secret"`
	IsAdmin    bool                   `json:"isAdmin"`
	Cred       *Credentials           `json:"cred"`
	String     string                 `json:"string"`
	Uint64     uint64                 `json:"uint64"`
}

type Credentials struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}
```

The first request must be a `Discover` command as shown in the following table. It returns a `DiscoverRes` object having information on the possibility of using the proxy (), and the managers that could be queried for changing the proxy state towards your client. `Discover`

| command                         |  response   |
|-------------------------------- | ----------- |
| {Cmd:Discover,Manager:RulesK}   | DiscoverRes |

The constants `Discover` and `RulesK` are defined in [cmd.go](cmd.go). `DiscoverRes` is defined:

```
type DiscoverRes struct {
	MatchMng map[string]*MatchType `json:"matchMng"`
	Result   string                `json:"result"`
}

type MatchType struct {
	Match bool   `json:"match"`
	Type  string `json:"type"`
}
```

`DiscoverRes.Result` means the client is able to use the proxy when its value is `"true"`, if is not `"false"` either means that some managers are present in the predicate serving as rule for connecting clients, but aren't properly defined in the configuration. `Discover.MatchMng` has the names of the managers that can be queried as keys associated to `MatchType` values. `MatchType.Match` means the manager allowed the client to use the proxy. `MatchType.Type` is the type of the manager, which defines which particular queries accepts. Following the available types of managers are described.

### sessionIPM

An abbreviation of _session IP matcher_. It allows clients to use the proxy when there's an opened session from their IP.

| command                          | response            |
| -------------------------------- | ------------------- |
| {Cmd:Open,Cred:Credentials}      | JSON Web Token(JWT) |
| {Cmd:Close,Secret:JWT}           | ∅                   |
| {Cmd:Get,Secret:JWT}             | ip-user dictionary  | 
| {Cmd:Renew,Secret:JWT}           | new JWT             |
| {Cmd:Check,Secret:JWT}           | ∅                   |

### dwnConsR

An abbreviation of _download consumption restrictor_. It always allows clients if the rule evaluation reaches it. Once it does it only processes connections requested by the proxy if the user consumption hasn't reached a quota that is reseted at regular intervals of time.

| command                                      | response  |
| -------------------------------------------- | --------- |
| {Cmd:GetOther,Secret:JWT,String:user}        | userInfo  |
| {Cmd:Get,Secret:JWT}                         | userInfo  |
| {Cmd:Set,Secret:JWT,String:user,Uint64:cons} | ∅         |
| {Cmd:Show}                    | DwnConsR in JSON format  |

```go
type UserInfo struct {
	Quota       string   `json:"quota"`
	Groups      []string `json:"groups"`
	Name        string   `json:"name"`
	UserName    string   `json:"userName"`
	Consumption string   `json:"consumption"`
	BytesQuota  uint64   `json:"bytesQuota"`
	BytesCons   uint64   `json:"bytesCons"`
}
```

## Command line client

The command line client, `pmcl`, queries the API in order to change the server state or get information about it. The following is the list of subcommands `pmcl` supports. 

- `discover` or `d`: Since the IP, time determine resources available for a client, before using the proxy is wise to know which one of them are assigned and their state. It needs the API server address as argument (ex. "https://proxy.org"). Once the client opens a session the address argument is optional, if the command is run at the same directory the command for opening a session ran successfuly (there's a file created there with login information, including the API server address).
- `login` or `l`: having with `-m` the name of a `SessionIPM` returned by `discover`, then user and password, it opens a session from the client's IP.
- `logout` or `o`: in the same directory a successful `login` was made it closes the session.
- `logged-users` or `lu`: prints a list of IP-user where every user opened a session at the associated IP. The manager is specified with `-m` or read from the file created in a successful login.
- `status` or `s`: prints the user who opened a session at that directory, consumption and quota if a `DwnConsR` was assigned. Otherwise it accepts a manager with `-m`. If an additional argument is passed, it is interpreted as an user name for getting his information, but only if the logged user has administration privileges.
- `reset` or `r`: in a directory where a successful `login` was made, resets the user's consumption, passing it as argument, if allowed and there's a `DwnConsR` assigned. Otherwise it can be specified with `-m`.
- `show` or `sh`: shows the manager with the name passed as argument
 
## Developing

PMProxy requires Go 1.13 or superior for compiling. The client and basic server code are in the root package, while the code related to _managers_, i.e, objects that control the connection behavior, are in the `managers` directory.

Creating and controlling connections, opening sessions and almost the rest of operations occurr as commands sent to managers (see `Serve` procedure at `serve.go`). Every manager responds to several commands, as the API documentation shows, these may be sent by the proxy server itself when a client requests a WWW content, or by the API server when a client tries to manipulate directly the server state. The `Load` procedure at `managers/conf.go` defines how the proxy and API servers issue those calls to the managers. 

There's a manager that dispatches all commands in the `managers/manager.go` file. When it's `exec` method is called with a `Cmd` instance it determines all the managers that need to handle that object in order to perform correctly the command. This is done by looking to the `manager.paths` field, which is populated when the server is loaded. All managers references are stored in `manager.mngs`, which is a mapping from names to `func(*Cmd)`, the particular `exec` method for each manager instance.

For example, `DwnConsR` requires `Cmd.User`, `Cmd.String` and `Cmd.Groups` properly defined before calling its `Get` command through the `DwnConsR.exec` method. This means the `manager.exec` method must call the proper command in the configured `mapDB` or `adDB` object, referenced by `DwnConsR.UserDBN`, for having the right values in `Cmd.String` and `Cmd.Groups`; but before that it the command `Get` at `ipUser` manager must be called for having `Cmd.User` defined. This is detailed in the `DwnConsR.paths` procedure.

## Deployment

For a server with high traffic soon the amount of opened connections will increase up to the default limit for each process, therefore you need to configure a limit more suited for you needs. Using [systemd][3] units makes easier running, restarting or stopping the process, with a particular connection amount limit.

As example you can put the following content in `/etc/systemd/system/pmproxy.service`:

```conf
[Unit]
Description=PMProxy Service
After=network.target

[Service]
Type=simple
User=root
LimitNOFILE=49152
WorkingDirectory=/root/.config/pmproxy
ExecStart=/usr/local/bin/pmproxy
Restart=on-abort

[Install]
WantedBy=multi-user.target
``` 

which increases the limit number of opened files (`LimitNOFILE`) up to 49152, when usually it's 1024 (it can be found in `/etc/security/limits.conf`). Since opened connections count as opened files, this solves the previously mentioned problem.

Also having [systemd][3] a configuration allows to see the logs with `journalctl -u pmproxy`. Otherwise `journalctl _PID=X`, where X is the `pmproxy` process ID, will do.


[0]: https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
[1]: https://godoc.org/github.com/lamg/rtimespan
[2]: https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol
[3]: https://en.wikipedia.org/wiki/Systemd 
