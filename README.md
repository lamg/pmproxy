# PMProxy

PMProxy wraps an HTTP proxy with procedures that process an HTTP/HTTPS request according information it carries like IP that made it, requested URL, user authenticated by an Active Directory in that IP, time it is made, downloaded amount of bytes made by the authenticated user, and rules involving that information.

These parameters for processing a request, determined by the information it carries, time and rules are:
- The parent proxy for making the request.
- The network interface for making the connection.
- The factor for multiplying the consumption made from that connection.
- The quota that limits the data amount to be downloaded.
- The consumption that stores the downloaded data amount.
- The connection delay.

There are several important parts of this program:

- Incoming connection handling (pmproxy.go and the files implementing the types and procedures used there).
	- (TODO be more specific here) connector.go
	- Quota is separated from consumption manager, because is a static resource that can be asociated to a matcher. The administrator has to ensure of associate quota and consumption manager using the same predicate, if he wants them to be associated.
- Connection handling configuration while running or booting.
	- res_admin.go

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

[Install]
WantedBy=multi-user.target
```

- The GOPATH variable is not meant to be an environment variable, it should be replaced by the actual GOPATH value, so `go get -u github.com/lamg/pmproxy` will deploy the `pmproxy` executable.

- Is important defining `LimitNOFILE=49152` because systemd ignores `/etc/security/limits.conf`. Otherwise according the user load, very soon the error `http: Accept error: accept tcp [::]:8080: accept4: too many open files` will appear. The limits configuration can be checked by executing:

```sh
cat /proc/`pidof pmproxy`/limits|grep 'Max open files'
```

## Tasks

- [x] Flexible restrictions and access to resources specifications
- [x] Replace redirection with a page informing the error and a link to the login page when needed.
- [ ] English grammar
- [ ] Slow operations not in GUI's main thread
- [ ] Add html template and parse it in NewPMProxy
- [ ] Automatic session closing
- [ ] Marshal and Unmarshal correctly

- [ ] general request processing pmproxy.go
- [ ] Redefine the project according the types in res_det.go
- [x] delay_manager.go
- [ ] resource [de]serialization persistence_graph.go
- [x] how much bandwith of a channel consumes a connection at given rate
- [ ] connector.go, request through proxy must be managed by the proxy itself
- [ ] configuration management
- [x] limit the amount of connections per client
- [ ] provide a list of URLs whose access doesn't add to user consumption
- [ ] provide the amount of opened connections to the user. Implies getting at hand all CLMng, probably using the persistence graph. Which is another interface to what underlies in PMProxy.Rd
- [x] priority of consumption coeficient
- [ ] Add names to CMng, DMng, CLMng to be able to serialize ResDet struct, in res_det.go