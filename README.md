# PMProxy

[![Build Status](https://travis-ci.com/lamg/pmproxy.svg?branch=master)](https://travis-ci.com/lamg/pmproxy) [![Coverage Status](https://coveralls.io/repos/github/lamg/pmproxy/badge.svg?branch=master)](https://coveralls.io/github/lamg/pmproxy?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/lamg/pmproxy)](https://goreportcard.com/report/github.com/lamg/pmproxy)

PMProxy wraps an HTTP proxy server with procedures that process each HTTP request according information it carries and a set of rules.

The information analyzed in each HTTP request is:
- client IP address
- Time it arrived
- requested URL

With that information, using an Active Directory server and a map of IPs and logged users (which is kept in memory) it gets
the user's groups in that Active Directory.

The rules are predicates (not, or, and) on the previous information, and they have connection parameters associated. These are:
- The parent proxy for making the request.
- The network interface for making the connection.
- The limit on data amount to be downloaded (quota).
- The factor determining how fast the quota is reached, which is a float that is multiplied by the amount of downloaded bytes (consumption).
- The connection delay.

## Installation

Go 1.11 is required since is the first with module support, and the project has some specific dependencies managed with it.

```sh
git clone https://github.com/lamg/pmproxy
cd pmproxy/cmd/pmproxy && go install
cd ../../..
```

## Usage

The following will start the server using example configuration files.

```sh
mkdir pmproxy-dir
cd pmproxy/cmd/pmproxy/
cp *.yaml *.pem ../../../pmproxy-dir
cd ../../../pmproxy-dir
pmproxy -c conf.yaml
```

Now configure your web browser (or another client) to use localhost:8081 as HTTP proxy server, and request any page visible in your network.

## Tasks

- [ ] simpler design based in proxy_spec.go's definitions.
  - [ ] Implement `Admin` interface (admin.go)
    - [ ] Implement managers
      - [ ] session (session.go)
      - [ ] connection limit
      - [ ] delay
      - [ ] quota consumption
      - [ ] rules
  - [x] Implement `RSpec` interface (rspec.go)
    - [ ] implement `IPMatcher` (session.go)