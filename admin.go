package pmproxy

import (
	"os"
	"sync"
)

type globAdm struct {
	adms   *sync.Map // admins
	cons   *sync.Map // consRs
	ipms   *sync.Map // ipMatchers
	ipUI   *sync.Map // ipUserInfs
	ipQs   *sync.Map // ipQuotas
	usrDBs *sync.Map // userDBs
	toSer  *sync.Map // toSers
	conf   *config
}

type toSer func() (string, interface{})

type admin func(*AdmCmd) ([]byte, error)

type ipQuota func(ip) uint64

type ipGroup func(ip) ([]string, error)
type ipUserInf struct {
	ipg ipGroup
	ipu ipUser
}

// AdmCmd is an administration command
type AdmCmd struct {
	Manager      string        `json: "mng"`
	Cmd          string        `json: "cmd"`
	User         string        `json: "user"`
	Pass         string        `json: "pass"`
	Pos          []int         `json: "pos"`
	Rule         *rule         `json: "rule"`
	Secret       string        `json: "secr"`
	RemoteIP     string        `json: "remoteIP"`
	MngName      string        `json: "mngName"`
	MngType      string        `json: "mngType"`
	Capacity     int64         `json: "capacity"`
	FillInterval time.Duration `json: "fillInterval"`
	IPUser       string        `json: "ipUser"`
	Limit        uint64        `json: "limit"`
	UserDB       *userDB       `json: "usrDB"`
	DialTimeout  time.Duration `json: "dialTimeout"`
	Group        string        `json: "group"`
	IsAdmin      bool          `json: "isAdmin"`
	CIDR         string        `json: "cidr"`
}

func (g *globAdm) exec(c *AdmCmd) (r []byte, e error) {
	adm, _ := g.conf.checkAdmin(cmd.Secret)
	cmd.IsAdmin = adm != ""
	v, ok := c.admins.Load(c.Manager)
	if ok {
		r, e = (v.(admin))(cmd)
	} else if c.Manager == "global" {
		var mng *manager
		switch c.Cmd {
		case "add-bwCons":
			bw := newBwCons(cmd.MngName, cmd.FillInterval,
				cmd.Capacity)
			mng = bw.manager()
		case "add-connCons":
			cn := newConnCons(cmd.MngName, cmd.Limit)
			mng = cn.manager()
		case "add-dwCons":
			dw := newDwn //TODO
		case "add-trCons":
		case "add-groupIPM":
		case "add-rangeIPM":
		case "add-sessionIPM":
		case "add-userIPM":
		case "add-userDB":
		case "del-manager":
		default:
			e = NoCmd(c.Cmd)
		}
		if mng != nil {
			g.mngs.Store(mng.Name, mng)
		}
	} else {
		e = NoMngWithName(c.Manager)
	}
	return
}

func (g *globAdm) persist(w io.Writer) (e error) {
	sm := make(map[string][]interface{})
	// for TOML array of tables
	g.toSer.Range(func(k, v interface{}) (ok bool) {
		ks, vm := k.(string), v.(toSer)
		tỹpe, mp := vm()
		if ks == tỹpe {
			viper.Set(ks, mp)
		} else {
			// vm is part of an array of tables
			sm[tỹpe] = append(sm[tỹpe], mp)
		}
		return
	})
	for k, v := range sm {
		viper.Set(k, v)
	}
	os.Rename(g.conf.file, g.conf.file+".back")
	viper.WriteConfigAs(g.conf.file)
	return
}

func NoKey(k string) (e error) {
	e = fmt.Errorf("No key %s", c.Group)
	return
}
