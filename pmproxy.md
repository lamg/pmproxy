# PMProxy

PMProxy seen as a protocol, specified by its grammar:
The "→" is a literal introduced for marking where ends input and starts output, it could have been introduced as literally "→", but a syntactic sugar was used instead since it is so common.

```
pmproxy = proxy | admin.
proxy = proxy_http_server http_request time state rules spec → (conn | http_response) state proxy.
admin = admin_http_server http_request → (rules | state) spec.
```

## File hierarchy

- proxy_spec.go
  - admin.go
    - rspec.go
      - session.go
        - crypt.go
  - json.go

## Type hierarchy

- ProxyCtl
  - clock.Clock
  - RSpec
    - Spec
      - ConsR
  - SpecCtx
    - RSpec
    - clock.Clock
    - logger TODO
  - Admin
    - AdmCmd

- simpleRSpec
  - Rule
    - IPMatcher

- SessionMng
  - Crypt
  - IPMatcher
  - Authenticator

## Interface implementations
- RSpec
  - simpleRSPec (rspec.go)

- Admin
  - SessionMng (session.go)
  - simpleRSpec (rspec.go)
  - manager (manager.go)
  - TODO command for managing managers

- IPMatcher
  - SessionMng (session.go)
  - rangeIPM (range_ipm.go)
  - groupIPM (group_ipm.go)
  - userIPM (user_ipm.go)

- IPUser
  - SessionMng

- Authenticator
  - Ldap (github.com/lamg/ldaputil)

- fields for initializing github.com/lamg/proxy.Proxy
  - SpecCtx (spec_conn.go)

- ConsR
  - trCons (time_range_cons.go)
  - bwCons (bandwidth_cons.go)
  - dwnCons (download_cons.go)
  - connCons (conn_amount_cons.go)
  - idCons, negCons (id_neg_cons.go)

## Initializers

- NewProxyCtl (configuration.go)
  - reads a TOML file
  - TODO
    - add TOML tags to struct fields
    - initialize UserM
    - add initialized managers to `mng`
- ProxyCtl
  - manager
  - simpleRSpec
  

## Commands accepted by managers

- SessionMng
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
      - sm: SessionMng
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