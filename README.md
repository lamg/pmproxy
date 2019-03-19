```
 ____  __  __ ____                      
|  _ \|  \/  |  _ \ _ __ _____  ___   _ 
| |_) | |\/| | |_) | '__/ _ \ \/ / | | |
|  __/| |  | |  __/| | | (_) >  <| |_| |
|_|   |_|  |_|_|   |_|  \___/_/\_\\__, |
                                  |___/ 
```

[![License Badge](https://img.shields.io/badge/License-AGPL%203%2B-blue.svg)](LICENSE) [![Build Status](https://travis-ci.com/lamg/pmproxy.svg?branch=master)](https://travis-ci.com/lamg/pmproxy) [![Coverage Status](https://coveralls.io/repos/github/lamg/pmproxy/badge.svg?branch=master)](https://coveralls.io/github/lamg/pmproxy?branch=master) [![Go Report Card](https://goreportcard.com/badge/github.com/lamg/pmproxy)](https://goreportcard.com/report/github.com/lamg/pmproxy)

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

## Implementation

The file hierarchy is the following:

- serve
  - conf (TODO manage managers, try to get valid ones from letsencrypt)
    - genCert (TODO proper copyright)
    - userInfo
    - dwnConsR
      - ipQuota 
    - sessionIPM
    - groupIPM
    - userDB (TODO, cache)
    - rules 
    - connMng
    - dialer (TODO manager interface)
      - logger
      - consR
      - spec
  - handlers
    
### Tests

- test discover command 

### Dependencies

- ipGroup: ipUser, userGroup
- groupIPM: ipGroup
- ipQuota: ipUser, userGroup
- dwnConsR: ipQuota

Simplified:

- groupIPM: ipUser, userGroup
- dwnConsR: ipUser, userQuota

- now session manager must store the userDB that made possible the user to open the session, this way the user has the name of the managers that contain his resources
- ipUser is a constant repeated at every consR and managerKF. The repetition can be eleminitade by lifting it to the root context where consR and managerKF exists.
- Command `discover` that returns the matching consR and ip matchers is needed, with their types

### TODO

- rules.go
	- get resources for request
	- initialize rules
	- create `*ipMatcher` type
