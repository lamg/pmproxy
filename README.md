```
 ____  __  __ ____                      
|  _ \|  \/  |  _ \ _ __ _____  ___   _ 
| |_) | |\/| | |_) | '__/ _ \ \/ / | | |
|  __/| |  | |  __/| | | (_) >  <| |_| |
|_|   |_|  |_|_|   |_|  \___/_/\_\\__, |
                                  |___/ 
```

[![License Badge][0]](LICENSE) [![Build Status][1]][2] [![Coverage Status][3]][4] [![Go Report Card][5]][6]

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

[0]: https://img.shields.io/badge/License-AGPL%203%2B-blue.svg
[1]: https://travis-ci.com/lamg/pmproxy.svg?branch=master
[2]: https://travis-ci.com/lamg/pmproxy
[3]: https://coveralls.io/repos/github/lamg/pmproxy/badge.svg?branch=master
[4]: https://coveralls.io/github/lamg/pmproxy?branch=master
[5]: https://goreportcard.com/badge/github.com/lamg/pmproxy
[6]: https://goreportcard.com/report/github.com/lamg/pmproxy
