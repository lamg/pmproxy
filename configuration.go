package pmproxy

import (
	"encoding/json"
	"fmt"
	"time"
)

type config struct {
	admins []string

	dialTimeout time.Duration
	lg          *logger
	crypt       *crypt
	file        string
}

func (c *config) admin(cmd *AdmCmd) (bs []byte, e error) {
	// TODO
	if cmd.IsAdmin {
		switch cmd.Cmd {
		case "set-timeout":
			c.dialTimeout = cmd.DialTimeout
		case "get-timeout":
			bs = []byte(c.dialTimeout.String())
		case "add-admin":
			c.admins = append(c.admins, cmd.User)
		case "del-admin":
			ib := func(i int) (b bool) {
				b = c.admins[i] == cmd.User
				return
			}
			b, i := bLnSrch(ib, len(c.admins))
			if b {
				c.admins = append(c.admins[:i], c.admins[i+1:]...)
			} else {
				e = NoAdmin(cmd.User)
			}
		case "get-admins":
			bs, e = json.Marshal(c.admins)
		default:
			e = NoCmd(cmd.Cmd)
		}
	}
	return
}

func (c *config) checkAdmin(secret string) (user string,
	e error) {
	user, e = c.crypt.Decrypt(secret)
	if e == nil {
		ib := func(i int) (b bool) {
			b = c.admins[i] == user
			return
		}
		b, _ := bLnSrch(ib, len(c.admins))
		if !b {
			e = NoAdmin(user)
		}
	}
	return
}

func NoAdmin(user string) (e error) {
	e = fmt.Errorf("No administrator with name %s", user)
	return
}

func NoCmd(name string) (e error) {
	e = fmt.Errorf("No command with name %s", name)
	return
}

func NoMngWithType(name, tpe string) (e error) {
	e = fmt.Errorf("No %s with name %s", tpe, name)
	return
}

func NoMngWithName(name string) (e error) {
	e = fmt.Errorf("No manager with name %s", name)
	return
}

const (
	dialTimeout  = "dialTimeout"
	loggerIPUser = "loggerIPUser"
	loggerAddr   = "loggerAddr"
	admins       = "admins"
	configT      = "config"
)

func (c *config) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		nameK:        configT,
		dialTimeout:  c.dialTimeout.String(),
		loggerIPUser: c.lg.IPUser,
		loggerAddr:   c.lg.Addr,
		admins:       c.admins,
	}
	tỹpe = configT
	return
}

func (c *config) init(m map[string]interface{},
	file string) (e error) {
	// TODO
	c.file = file
	c.lg = new(logger)
	fs := []*string{&c.ad.Addr, &c.ad.Bdn, &c.ad.Pass,
		&c.ad.Suff, &c.ad.User, &c.lg.ipUser, &c.lg.Addr,
	}
	ks := []string{adAddr, adBdn, adPass, adSuff, adUser,
		loggerIPUser, loggerAddr,
	}
	ib := func(i int) (ok bool) {
		v, b := mp[ks[i]]
		if b {
			*fs[i], b = v.(string)
		}
		ok = !b
		return
	}
	ok, i := bLnSrch(ib, len(ks))
	if ok {
		e = NoKeyType(ks[i], "string")
	}
	if e == nil {
		v, ok := m[admins]
		if ok {
			c.admins, ok = v.([]string)
		}
		if !ok {
			e = NoKeyType(admins, "[]string")
		}
	}
	var dur string
	if e == nil {
		v, ok := m[dialTimeout]
		if ok {
			dur, ok = v.(string)
		}
		if !ok {
			e = NoKeyType(dialTimeout)
		}
	}
	if e == nil {
		c.dialTimeout, e = time.ParseDuration(dur)
	}
	if e == nil {
		c.crypt, e = newCrypt()
	}
	return
}

func (c *config) timeout() (d time.Duration) {
	d = c.dialTimeout
	return
}
