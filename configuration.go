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
}

const (
	dialTimeoutK  = "dialTimeout"
	adminsK       = "admins"
	loggerIPUserK = "loggerIPUser"
	loggerAddrK   = "loggerAddr"
	configT       = "config"
)

func (c *config) admin(cmd *AdmCmd, fb func([]byte),
	fe func(error)) (cs []cmdProp) {
	// TODO
	if cmd.IsAdmin {
		cs = []cmdProp{
			{
				cmd:  set,
				prop: dialTimeoutK,
				f:    func() { c.dialTimeout = cmd.DialTimeout },
			},
			{
				cmd:  get,
				prop: dialTimeoutK,
				f:    func() { fb([]byte(c.dialTimeout.String())) },
			},
			{
				cmd:  add,
				prop: adminsK,
				f:    func() { c.admins = append(c.admins, cmd.User) },
			},
			{
				cmd:  del,
				prop: adminsK,
				f: func() {
					ib := func(i int) (b bool) {
						b = c.admins[i] == cmd.User
						return
					}
					b, i := bLnSrch(ib, len(c.admins))
					if b {
						c.admins = append(c.admins[:i], c.admins[i+1:]...)
					} else {
						fe(NoAdmin(cmd.User))
					}
				},
			},
			{
				cmd:  get,
				prop: adminsK,
				f: func() {
					bs, e := json.Marshal(c.admins)
					fb(bs)
					fe(e)
				},
			},
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

func (c *config) toSer() (tỹpe string, i interface{}) {
	i = map[string]interface{}{
		nameK:         configT,
		dialTimeoutK:  c.dialTimeout.String(),
		loggerIPUserK: c.lg.IPUser,
		loggerAddrK:   c.lg.Addr,
		adminsK:       c.admins,
	}
	tỹpe = configT
	return
}

func (c *config) fromMapKF(fe ferr) (kf []kFuncI) {
	kf = []kFuncI{
		{
			adminsK,
			func(i interface{}) {
				c.admins = stringSliceE(i, fe)
			},
		},
		{
			dialTimeoutK,
			func(i interface{}) {
				c.dialTimeout = stringDurationE(i, fe)
			},
		},
		{
			loggerAddrK,
			func(i interface{}) {
				c.lg = new(logger)
				c.lg.Addr = stringE(i, fe)
			},
		},
		{
			loggerIPUserK,
			func(i interface{}) {
				c.lg.IPUser = stringE(i, fe)
			},
		},
		{
			loggerIPUserK,
			func(i interface{}) {
				fe(c.lg.init())
			},
		},
	}
	return
}

func (c *config) timeout() (d time.Duration) {
	d = c.dialTimeout
	return
}
