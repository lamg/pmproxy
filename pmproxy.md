# PMProxy

PMProxy seen as a protocol, specified by its grammar:
The "→" is a literal introduced for marking where ends input and starts output, it could have been introduced as literally "→", but a syntactic sugar was used instead since it is so common.

```
pmproxy = (proxy | spec) pmproxy.
proxy = proxy_http_server http_request time state rules spec → (conn | http_response) state.
spec = control_http_server http_request → (rules | state).
```