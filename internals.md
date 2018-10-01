# Internals

## Design

There are several important parts of this program:

- Incoming connection handling (connector.go and the files implementing the types and procedures used there).
	- Quota is separated from consumption manager, because is a static resource that can be asociated to a matcher. The administrator has to ensure of associate quota and consumption manager using the same predicate, if he wants them to be associated.
- Connection handling configuration while running or booting.
	- state_manager.go loads and persists the state of the program

## PMProxy deployment

PMProxy is deployed as a systemd service in this case. The following conditions must be true:

- pmproxy executable must be in `/usr/local/bin/pmproxy`.

- A configuration file must be created with the format described above (ex. conf.yaml) (currently configuration is in JSON format).

- A certificate and a private key files must be created, with PEM format (ex. cert.pem and key.pem).

- A quotas file with the format described above must be created. Notice that with an empty map the proxy will not respond to any requests (ex. quotas.json).

- A consumptions file with consumption cycle duration and last consumption cycle end's date fields are mandatory (ex. cons.json).

- An access exceptions file with the format described above. The array of JSON objects may be empty (ex. `[]` in accExcp.json file).

- The previously described files must be in `/etc/pmproxy/` directory.

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