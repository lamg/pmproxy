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

func (c *config) exec(cmd *AdmCmd) (bs []byte, e error) {
	if cmd.IsAdmin {
		switch cmd.Cmd {
		case "set-timeout":
			c.DialTimeout = cmd.DialTimeout
		case "get-timeout":
			r = c.DialTimeout.String()
		case "add-admin":
			c.Admins = append(c.Admins, cmd.User)
		case "del-admin":
			ib := func(i int) (b bool) {
				b = c.Admins[i] == cmd.User
				return
			}
			b, i := bLnSrch(ib, len(c.Admins))
			if b {
				c.Admins = append(c.Admins[:i], c.Admins[i+1:]...)
			} else {
				e = NoAdmin(cmd.User)
			}
		case "get-admins":
			bs, e = json.Marshal(c.Admins)
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
			b = c.Admins[i] == user
			return
		}
		b, _ := bLnSrch(ib, len(c.Admins))
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
	adAddr       = "adAddr"
	adUser       = "adUser"
	adPass       = "adPass"
	adBdn        = "adBdn"
	adSuff       = "adSuff"
	dialTimeout  = "dialTimeout"
	loggerIPUser = "loggerIPUser"
	loggerAddr   = "loggerAddr"
	admins       = "admins"
)

func (c *config) toMap() (m map[string]interface{}) {
	m = map[string]interface{}{
		adAddr:       c.ad.Addr,
		adUser:       c.ad.User,
		adPass:       c.ad.Pass,
		adBdn:        c.ad.Bdn,
		adSuff:       c.ad.Suff,
		dialTimeout:  c.dialTimeout.String(),
		loggerIPUser: c.lg.ipUser,
		loggerAddr:   c.lg.Addr,
		admins:       c.admins,
	}
	return
}

func (c *config) init(m map[string]interface{},
	file string) (e error) {
	c.file = file
	c.ad = new(adConf)
	c.lg = new(lg)
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

func (c *config) manager() (m *manager) {
	m = &manager{
		name:  "config",
		tỹpe:  "config",
		cons:  idCons(),
		mtch:  idMatch,
		adm:   c.exec,
		toMap: c.toMap,
	}
	return
}

func (c *config) adConf() (a *adConf) {
	a = c.ad
	return
}

func (c *config) timeout() (d time.Duration) {
	d = c.dialTimeout
	return
}
