# PMProxy

PMProxy seen as a protocol, specified by its grammar:
The "→" is a literal introduced for marking where ends input and starts output, it could have been introduced as literally "→", but a syntactic sugar was used instead since it is so common.

```ebnf
pmproxy = proxy | admin.
proxy = proxy_http_server http_request time state rules spec → (conn | http_response) state proxy.
admin = admin_http_server http_request → (rules | state) spec.
```

## Type hierarchy

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

## TODO
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
- implement NewProxyCtl:
  - readAD
  - readAdms
  - readBwCons
  - readConnCons
  - readTimeout
  - readDwnCons
  - readLogger
  - readRangeIPM
  - readRspec
  - readSessionIPM
  - readUserIPM
  - setDefaults
- NewProxyCtl

## Commands accepted by managers

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

## Initial configuration example
