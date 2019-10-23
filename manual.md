# Manual

## Introduction

An HTTP proxy server is an HTTP server which is used as intermediary between the clients requesting contents from the Word Wide Web, through browsers mainly, and the remote servers that provide it. In that position is possible to control which and how those requests are processed and responded. 

PMProxy is an HTTP proxy server with fine grained control over the connections made through it. It relies on a predicate, supplied in the configuration, which is evaluated (to `true` or `false`) according the parameters of each requests. The connection is made if and only if the predicate is evaluated to `true`.

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

| commando                         |  response   |
|--------------------------------- | ----------- |
| {Cmd:Discover,Manager:RulesK}    | DiscoverRes |

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

## sessionIPM

An abbreviation of _session IP matcher_. It allows clients to use the proxy when there's an opened session from their IP.

| command                          | response            |
| -------------------------------- | ------------------- |
| {Cmd:Open,Cred:Credentials}      | JSON Web Token(JWT) |
| {Cmd:Close,Secret:JWT}           | ∅                   |
| {Cmd:Get,Secret:JWT}             | ip-user dictionary  | 
| {Cmd:Renew,Secret:JWT}           | new JWT             |
| {Cmd:Check,Secret:JWT}           | ∅                   |

## dwnConsR

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
