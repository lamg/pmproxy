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
  - ProxySpec
    - Spec
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
  - simpleRSPec

- Admin
  - SessionMng
  - simpleRSpec

- IPMatcher
  - SessionMng (session.go)
  - rangeIPM (range_ipm.go)
  - groupIPM (group_ipm.go)
  - userIPM (user_ipm.go)

- IPUser
  - SessionMng

- Authenticator
  - Ldap (github.com/lamg/ldaputil)

- Transport 
  - specTransport (spec_transport.go) TODO

- ConsR
  - trCons (time_range_cons.go)
  - bwCons (bandwidth_cons.go)
  - dwnCons (download_cons.go)
  - connCons (conn_amount_cons.go)
  - idCons, negCons (id_neg_cons.go)