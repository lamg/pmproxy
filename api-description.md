# API description

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
