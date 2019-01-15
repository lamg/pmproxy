package pmproxy

import (
	"os"
	"sync"
)

type globAdm struct {
	mngs *sync.Map
	conf *config
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

type matcher func(string) bool

func idMatch(s string) (b bool) {
	b = true
	return
}

type admin func(*AdmCmd) ([]byte, error)

// AdmCmd is an administration command
type AdmCmd struct {
	Manager      string        `json:"mng"`
	Cmd          string        `json:"cmd"`
	User         string        `json:"user"`
	Pass         string        `json:"pass"`
	Pos          []int         `json:"pos"`
	Rule         *rule         `json:"rule"`
	Secret       string        `json:"secr"`
	RemoteIP     string        `json:"remoteIP"`
	MngName      string        `json:"mngName"`
	MngType      string        `json:"mngType"`
	Capacity     int64         `json:"capacity"`
	FillInterval time.Duration `json:"fillInterval"`
	IPUser       string        `json:"ipUser"`
	Limit        uint64        `json:"limit"`
	AD           *adConf       `json:"ad"`
	DialTimeout  time.Duration `json:"dialTimeout"`
	Group        string        `json:"group"`
	IsAdmin      bool          `json:"isAdmin"`
}

// consR stands for consumption restrictor,
// it restricts several aspects of a connection
type consR struct {
	Name   string `json: "name"`
	open   func(ip) bool
	can    func(ip, download) bool
	update func(ip, download)
	close  func(ip)
}

type download int
type ip string

func idCons() (c *consR) {
	c = &consR{
		Name: "id",
		open: func(i ip) (b bool) { b = true; return },
		can: func(i ip, d download) (b bool) {
			b = true
			return
		},
		update: func(i ip, d download) {},
		close:  func(i ip) {},
	}
	return
}

func (g *globAdm) exec(c *AdmCmd) (r []byte, e error) {
	adm, _ := g.conf.checkAdmin(cmd.Secret)
	cmd.IsAdmin = adm != ""
	v, ok := c.mngs.Load(c.Manager)
	if ok {
		r, e = v.(*manager).adm.exec(cmd)
	} else if c.Manager == "global" {
		switch c.Cmd {
		case "add-bwCons":
		case "add-connCons":
		case "add-dwCons":
		case "add-trCons":
		case "add-groupIPM":
		case "add-rangeIPM":
		case "add-sessionIPM":
		case "add-userIPM":
		case "del-manager":
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
