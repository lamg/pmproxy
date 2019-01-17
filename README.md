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

## Work in progress

Please don't be such a fundamentalist on this is being done at the master branch. Checkout tag `v0.2` for getting the last working version.

### Type hierarchy

- ProxyCtl (proxy_ctl.go)
  - SpecCtx (spec_conn.go)
    - rspec
  - config
    - rspec
    - admin

- rspec (rspec.go)
  - matcher
  - consR

- matcher
  - sessionIPM
  - userIPM
  - groupIPM
  - rangeIPM

- consR
  - bwCons
  - connCons
  - dwnCons
  - trCons

### TODO
- simpler configuration parsing with proper error reporting
- tight fields and methods visibility
- the matcher can leave information provided by IPUser making it superflous
- Information needed by
  - dwnConsR: user, group
  - userIPM: user
- show users the resources available for them
- not so strict error handling
- github.com/lamg/goproxy and github.com/lamg/proxy benchmark
- client login
- NewProxyCtl
  - implementation of manager
  - sessionIPM wip
- Test "github.com/juju/ratelimit"
- Build proxy with fasthttp

### Commands accepted by managers

- sessionIPM
  - open
    - params: user, password
    - returns: secret
  - close
    - params: secret
  - show
    - params: secret
    - spec: if the user in secret is an administrator then show the opened sessions

- simpleRSpec
  - add
    - params: secret, pos, rule
    - spec: if the user in secret is an administrator then add rule.
  - del
    - params: secret, pos, rule
    - spec: if the user in secret is an administrator then delete rule
  - show
    - params: secret
    - spec: returns a JSON representation fo rules

- manager
  - add
    - params: secret, type, name, args
    - spec: adds a manager if secret is from an administrator with the type, name and interpreting the specific args. Adding a rule requires some preprocessing because the rule inside a command doesn't have a direct reference to the value needed by simpleRule.Spec for giving the correct result.
    - types:
      - sm: sessionIPM
        - params: Active Directory (AD) address, AD user, AD password, administrators list
      - tr: trCons
        - params: start, end, active duration, total duration, times, infinite times, always
      - bw: bwCons
        - params: capacity, fill interval
      - dw: dwnCons
        - params: IPUser name, limit
      - cn: connCons
        - params: limit
      - id: idCons
        - params: none
      - ng: negCons
        - params: none
  - del:
    - params: secret, name
    - spec: deletes the manager with that name if the secret is from an administrator
  - show:
    - params: secret
    - spec: sends a JSON representation of managers

### Initial configuration example
