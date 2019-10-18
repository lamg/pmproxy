```
 ____  __  __ ____                      
|  _ \|  \/  |  _ \ _ __ _____  ___   _ 
| |_) | |\/| | |_) | '__/ _ \ \/ / | | |
|  __/| |  | |  __/| | | (_) >  <| |_| |
|_|   |_|  |_|_|   |_|  \___/_/\_\\__, |
                                  |___/ 
```

[![License Badge][0]](LICENSE) [![Build Status][1]][2] [![Coverage Status][3]][4] [![Go Report Card][5]][6]

PMProxy is an HTTP proxy server which uses a predicate for allowing or forbidding requests, and assigning resources to them once they are allowed.
 
The predicate contains references as identifiers, which point to _managers_ that analyzing:
- the client IP address
- the time the request was made
- and the requested URL

return `true` or `false` when the predicate is evaluated with a specific request.

There are also managers that once they are reached by the predicate evaluation always return `true`, but also set themselves as handlers of the connections made by that client.

## Configuration example

The [sessionIPM](api-description.md/#sessionIPM) manager only returns `true` when the client, identified by its IP address, authenticated against it, with valid credentials according a configured database. The [dwnConsR](api-description.md/#dwnConsR) manager always returns `true`, but every downloaded amount by a client (identified by the IP address from which it authenticated) is accumulated until it reaches a quota. Then the connections by that client are denied, until a reset occurs manually or at regular time intervals.

The following configuration will only allow connections from IPs authenticated by `session:sessionIPM`, and will have 1 GB for downloading each day:

```toml
rule = "sessions ∧ down"

[sessionIPM]
	name = "sessions"
	auth = "map"

[dwnConsR]
	name = "down"
	userDBN = "map"
	resetCycle = "24h"
	[dwnConsR.groupQuota]
		group0 = "1 GB"

[mapDB]
	name = "map"
	[mapDB.userPass]
		user0 = "pass0"
	[mapDB.userGroup]
		user0 = ["group0"]
```

The previous content must be placed at `$HOME/.config/pmproxy/managers.toml`.

Also there's a separate file for the servers (proxy and API) configuration, that must be placed at `$HOME/.config/pmproxy/server.toml`.An example content is:

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
		fastOrStd=true

[proxy]
	dialTimeout="10s"
	[proxy.server]
		readTimeout="30s"
		writeTimeout="20s"
		addr=":8080"
		fastOrStd=true
```

With the previous configuration the [pmproxy](cmd/pmproxy) command will start an HTTP proxy server at `:8080`, and an HTTPS [API](api-description.md) server at `:4443`. Then you can use your browser with `pmproxy-server-address:8080` as your HTTP proxy, and `https://pmproxy-server-address:4443` as argument to `pmcl` while discovering and querying assigned managers according the predicate. The `excludedRoutes` field is a list of routes that a web interface, served from the `webStaticFilesDir`, handles without requesting them to the server.

## Client usage example

Running the proxy with the previous configuration at `localhost`, the command `pmcl d https://localhost:4443` will return:

```
Match result: false
[❌] sessions:sessionIPM
```

With that, and knowing the credentials configured at the `mapDB` object in `managers.toml`, it's possible to log in with `pmcl l -m sessions https://localhost:4443 user0 pass0`. This will create a file `login.secret` at the current path with information for `pmcl` to work properly. Then the command `pmcl s` will return:

```
User: user0
Name: user0
Groups: [group0]
Quota: 1 GB Consumption: 0 B
```

and `pmcl d`:

```
Match result: true
[✅] down:DwnConsR
[✅] sessions:sessionIPM
```

## Deployment

For a server with high traffic soon the amount of opened connections will increase up to the default limit for each process, therefore you need to configure a limit more suited for you needs. Using [systemd][7] units makes easier running, restarting or stopping the process, with a particular connection amount limit.

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

Also having [systemd][7] a configuration allows to see the logs with `journalctl -u pmproxy`. Otherwise `journalctl _PID=X`, where X is the `pmproxy` process ID, will do.

[0]: https://img.shields.io/badge/License-AGPL%203%2B-blue.svg
[1]: https://travis-ci.com/lamg/pmproxy.svg?branch=master
[2]: https://travis-ci.com/lamg/pmproxy
[3]: https://coveralls.io/repos/github/lamg/pmproxy/badge.svg?branch=master&service=github
[4]: https://coveralls.io/github/lamg/pmproxy?branch=master
[5]: https://goreportcard.com/badge/github.com/lamg/pmproxy
[6]: https://goreportcard.com/report/github.com/lamg/pmproxy
[7]: https://en.wikipedia.org/wiki/Systemd
