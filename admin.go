package pmproxy

import (
	"os"
	"sync"
)

type globAdm struct {
	adms   *sync.Map
	cons   *sync.Map
	ipms   *sync.Map
	ipgs   *sync.Map
	usrDBs *sync.Map
	toSer  *sync.Map
	conf   *config
}

type manager struct {
	name  string
	tỹpe  string
	cons  *consR
	mtch  matcher
	adm   admin
	toSer func() interface{}
	// to serializable by viper type
	// like []map[string]interface{} or map[string]interface{}
}

type admin func(*AdmCmd) ([]byte, error)

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
	v, ok := c.mngs.Load(c.Manager)
	if ok {
		r, e = v.(*manager).adm.exec(cmd)
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
			dw := newDwn
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
	g.mngs.Range(func(k, v interface{}) (ok bool) {
		ks, vm := k.(string), v.(*manager)
		mp := vm.toSer()
		if vm.name == vm.tỹpe {
			viper.Set(ks, mp)
		} else {
			// vm is part of an array of tables
			sm[vm.tỹpe] = append(sm[vm.tỹpe], mp)
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
