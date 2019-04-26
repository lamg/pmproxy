# PMProxy

PMProxy is a proxy server based on <https://github.com/lamg/goproxy> which is a fork of <https://github.com/elazarl/goproxy>. This proxy server processes requests and responses according the following
detailed descriptions.

## Request processing

- Requests made from an IP with not logged user are redirected to the web interface.

- Requests made from an IP with a logged user, but with consumed quota are redirected to the web interface.

- Requested amount of data increases the user's consumption. The increment of user's consumption isdetermined by adding to the current user's consumption a product of a number by the downloaded amount of data. The number is determined according parameters like user's IP, user's remaining quota, user's data available on Active Directory, the time the request is made. A negative number means the request must be denied.

## Response processing

- Responses are logged in files with Squid log format
- Responses are filtered according a set of restrictions like the MIME type.

## Quotas and consumption

- Quotas are determined by user's associated information in the Active Directory.

- Consumption is determined by user's IP, time of request,and requested address.

- Consumptions are reseted cyclically.

## Sessions

- An user can open a sessions from only one IP. If an user uses the credentials of an already opened session the latter is closed and is redirected to the web interface with a suitable notification.

- A session is automatically closed if is inactive by a determined time period.

## REST API

```go
Cred {
  "user" string,
  "pass" string
}

User {
  "userName" string,
  "name" string,
  "isAdmin" bool,
  "quotaGroup" uint64
}

NameVal {
  "name" string,
  "value" uint64
}

LogRs {
  "scrt" string // this is the string sent in the header
}
```

- AHd = Header["authHd"] is the string returned in LogRs
- Cd = 200 or 400
- Rc = Response code
- Rb = Response body

| Path            | Method | Header  | Body | Rc | Rb    |
|-----------------|--------|---------|------|----|-------|
| /api/auth       | POST   | Cred    |      | Cd | LogRs |
| /api/auth       | DELETE |         | AHd  | Cd |       |
| /api/userStatus | GET    |         | AHd  | Cd | QtCs  |
| /api/userStatus | PUT    | NameVal | AHd  | Cd |       |
| /api/checkUser  | GET    |         | AHd  | Cd |       |
| /api/userInfo   | GET    |         | AHd  | Cd | User  |

## PMProxy clients

There are two clients, `pmuser` and `pmuser-gtk`. The former is a command line program, and the latter, as its name indicates, a GUI in GTK+.

## Configuration file

The configuration file is in JSON format. Following is the configuration fields description.

- ipRanges: []string. Each string is an IP range in CIDR notation. It specifies which IPs have access to the proxy service.

- proxySrvAddr: string. Has the form host:port. It specifies the address and port for running the proxy server.

- grpIface: map[string]string. It specifies the mapping between user groups and network interfaces for processing the requests. This way the request from an user from group X, will be made using the associated network interface in the map for group X.

- grpThrottle: map[string]string. It specifies the mapping between user groups and connection throttling fractions. 1 means no throttle, and 0 no connection.

- grpQtPref: string. Is the prefix of the user's group that determines the quota group (which is the rest of the group's name)

- logBName: string. Log's path and base name joined. Log files will be stored in path with base name equal to the provided concatenated with a number which represents the date the file was created. Example, with "logs/access.log" will store the log files in "log/" with name "access20171101145959.log". If empty no log will be produced.

- accExcp: string. Path of the accExcp file, which contains a JSON array where each element is an object that specifies an access exception for an URL. These objects have a field "hostRE" with a regular expression as value, a field "start" with a time in RFC3339 format, a field "end" with the previous format, and a number. The latter values are strings except the last. The regular expression is used for matching a host, the start and end times for specifying a time interval, and the number is a coeficient for multiplying the amount of downloaded data and adding the result to the user's consumption. In case the the number is negative it means no access. This way the requests to matched hosts inside the specified time interval get the associated coeficient, if no match occurs the coeficient is 1.

- cons: string. Path to the consumptions file. This file contains a JSON object which has the duration of a consumption cycle, at the end of which all consumptions are set to 0. The next field is the date of the last's consumption cycle end.

- quota: string. Path to the quotas file. This file contains a JSON map which associates to user groups an amount of bytes, which is the uper limit of consumption by each user in the group in a consumption cycle.

- admGrp: string. Is the group of the proxy administrators. These users have privileges like setting manually the consumption.

- stPath: string. Path to serve static files.

- loginAddr: string. URL of the web interface.

- certFl: string. Path of the cert.pem file used for starting the HTTPS server.

- keyFl: string. Path of the key.pem file used for starting the HTTPS server and for the JWT (JSON Web Token) library.

- adAddr: string. Active Directory's host:port.

- adAccSf: string. Active Directory's accounts suffix.

- bdn: string. Active Directory's base distinguished name.

## PMProxy deployment

PMProxy is deployed as a systemd service in this case. The following conditions must be true:

- pmproxy executable must be in `/usr/local/bin/pmproxy`.

- A configuration file must be created with the format described above (ex. conf.yaml) (currently configuration is in JSON format).

- A certificate and a private key files must be created, with PEM format (ex. cert.pem and key.pem).

- A quotas file with the format described above must be created. Notice that with an empty map the proxy will not respond to any requests (ex. quotas.json).

- A consumptions file with consumption cycle duration and last consumption cycle end's date fields are mandatory (ex. cons.json).

- An access exceptions file with the format described above. The array of JSON objects may be empty (ex. `[]` in accExcp.json file).

- The previosly described files must be in `/etc/pmproxy/` directory.

- A service file must be created and placed in `/etc/systemd/system/pmproxy.service` Below there's an example of its contents.

```conf
[Unit]
Description=PMProxy Service
After=network.target

[Service]
Type=simple
User=root
LimitNOFILE=49152
WorkingDirectory=/etc/pmproxy
ExecStart=$GOPATH/bin/pmproxy -c /etc/pmproxy/conf.json
Restart=on-abort
StandarOutput=syslog
StandardOutput=syslog
SyslogIdentifier=pmproxy

[Install]
WantedBy=multi-user.target
```

- The GOPATH variable is not meant to be an environment variable, it should be replaced by the actual GOPATH value, so `go get -u github.com/lamg/pmproxy` will deploy the `pmproxy` executable.

- Is important defining `LimitNOFILE=49152` because systemd ignores `/etc/security/limits.conf`. Otherwise according the user load, very soon the error `http: Accept error: accept tcp [::]:8080: accept4: too many open files` will appear. The limits configuration can be checked by executing:

```sh
cat /proc/`pidof pmproxy`/limits|grep 'Max open files'
```

## Tasks

- [ ] Flexible restrictions and access to resources specifications
- [ ] Replace redirection with a page informing the error and a link to the login page when needed.
- [ ] English grammar
- [ ] Slow operations not in GUI's main thread
- [ ] Add html template and parse it in NewPMProxy

### Error

```
panic: runtime error: slice bounds out of range
bytes.(*Buffer).Write(0xc000160570, 0xc013ffe000, 0xbfc5, 0x103ff, 0x81fbfe, 0x1, 0x0)
        /home/lamg/golang/src/bytes/buffer.go:177 +0x108
encoding/json.(*Encoder).Encode(0xc00c677af0, 0x782820, 0xc009b91fb0, 0x0, 0x0)
        /home/lamg/golang/src/encoding/json/stream.go:225 +0x1cb
github.com/lamg/pmproxy.Encode(0x89c600, 0xc000160570, 0x782820, 0xc009b91fb0, 0xc0053a7ba0, 0x40ad5b)
        /home/lamg/proyectos/pmproxy/local_handler.go:239 +0xcf
github.com/lamg/pmproxy.(*ConsMap).fillBuffer(0xc000066980)
        /home/lamg/proyectos/pmproxy/cons_map.go:118 +0x10d
github.com/lamg/pmproxy.(*ConsMap).Store(0xc000066980, 0xc006876dd0, 0xd, 0x731fd3b)
        /home/lamg/proyectos/pmproxy/cons_map.go:92 +0x167
github.com/lamg/pmproxy.(*QAdm).cons(0xc000066a80, 0xc0027b8ea0, 0x11, 0xc0044eaf67, 0x1a, 0x23, 0x0)
        /home/lamg/proyectos/pmproxy/qadm.go:149 +0x22c
github.com/lamg/pmproxy.(*conCount).Read(0xc006be3e00, 0xc00d6d6000, 0x8000, 0x8000, 0x5b8, 0x0, 0x0)
        /home/lamg/proyectos/pmproxy/restr_conn.go:18 +0xd3
github.com/lamg/pmproxy.(*thConn).Read(0xc00365fbc0, 0xc00d6d6000, 0x8000, 0x8000, 0x5b8, 0x0, 0x0)
        /home/lamg/proyectos/pmproxy/req_conn_manager.go:191 +0x63
io.copyBuffer(0x89d660, 0xc00016d000, 0x7efdc1a8ba00, 0xc00365fbc0, 0xc00d6d6000, 0x8000, 0x8000, 0xc0
        /home/lamg/golang/src/io/io.go:402 +0x122
io.Copy(...)
        /home/lamg/golang/src/io/io.go:364
net.genericReadFrom(...)
        /home/lamg/golang/src/net/net.go:614
net.(*TCPConn).readFrom(0xc00075ed88, 0x7efdc1a8ba00, 0xc00365fbc0, 0xc0027226b8, 0x40b28a, 0x7b96c0)
        /home/lamg/golang/src/net/tcpsock_posix.go:54 +0x13d
net.(*TCPConn).ReadFrom(0xc00075ed88, 0x7efdc1a8ba00, 0xc00365fbc0, 0x7efdc1a8ba40, 0xc00075ed88, 0x43
        /home/lamg/golang/src/net/tcpsock.go:103 +0x4e
io.copyBuffer(0x89cb60, 0xc00075ed88, 0x7efdc1a8ba00, 0xc00365fbc0, 0x0, 0x0, 0x0, 0xc009321640, 0x89c
        /home/lamg/golang/src/io/io.go:388 +0x2fc
io.Copy(...)
        /home/lamg/golang/src/io/io.go:364
github.com/lamg/goproxy.copyOrWarn(0xc00606fea0, 0x89cb60, 0xc00075ed88, 0x7efdc1a8ba00, 0xc00365fbc0,
        /home/lamg/go/pkg/mod/github.com/lamg/goproxy@v0.0.0-20190426172008-70085d574b4a/https.go:290 
created by github.com/lamg/goproxy.(*ProxyHttpServer).handleHttps.func1
        /home/lamg/go/pkg/mod/github.com/lamg/goproxy@v0.0.0-20190426172008-70085d574b4a/https.go:115
```

