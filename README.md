# PMProxy

PMProxy is a proxy server based on <https://github.com/lamg/goproxy> which is a fork of <https://github.com/elazarl/goproxy>. This proxy server processes requests and responses according the following
detailed descriptions.

## Request processing

- Requests made from an IP with not logged user are redirected to the web interface.

- Requests made from an IP with a logged user, but withconsumed quota are redirected to the web interface.

- Requested amount of data increases the user's consumption. The increment of user's consumption isdetermined by adding to the current user's consumption a product of a number by the downloaded amount of data. The number is determined according parameters like user's IP, user's remaining quota, user's data available on Active Directory, the time the request is made. A negative number means the request must be denied.

## Response processing

- Responses are logged in files with Squid log format
- Responses are filtered according a set of restrictions like the MIME type.

## Quotas and consumption

- Quotas are determined by user's associated information in the Active Directory.

- Consumption is determined by user's IP, time of request,and requested address.

- Consumptions are reseted cyclically.

## Sessions

- An user can open a sessions from only one IP. If an user uses the credentials of an already opened session the latter is closed and is redirected to the web interface with a suitable notification.

- A session is automatically closed if is inactive by a determined time period.

## REST API

```go
Cred {
  "user" string,
  "pass" string
}

User {
  "userName" string,
  "name" string,
  "isAdmin" bool,
  "quotaGroup" uint64
}

NameVal {
  "name" string,
  "value" uint64
}

LogRs {
  "scrt" string // this is the string sent in the header
}
```

- AHd = Header["authHd"] is the string returned in LogRs
- Cd = 200 or 400
- Rc = Response code
- Rb = Response body

| Path            | Method | Header  | Body | Rc | Rb    |
|-----------------|--------|---------|------|----|-------|
| /api/auth       | POST   | Cred    |      | Cd | LogRs |
| /api/auth       | DELETE |         | AHd  | Cd |       |
| /api/userStatus | GET    |         | AHd  | Cd | QtCs  |
| /api/userStatus | PUT    | NameVal | AHd  | Cd |       |
| /api/checkUser  | GET    |         | AHd  | Cd |       |
| /api/userInfo   | GET    |         | AHd  | Cd | User  |

## PMProxy clients

There are two clients, `pmuser` and `pmuser-gtk`. The former is a command line program, and the latter, as its name indicates, a GUI in GTK+. TODO slow operations not
in the main thread.

## Tasks

- Redirect URL with information on the cause of redirection
- Flexible restrictions and access to resources specifications