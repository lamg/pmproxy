package pmproxy

import (
	"github.com/spf13/viper"
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
	toMap func() map[string]interface{}
}

type matcher func(string) bool

func idMatch(s string) (b bool) {
	b = true
	return
}

type admin func(*AdmCmd) ([]byte, error)

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
	sm := make(map[string][]map[string]interface{})
	g.mngs.Range(func(k, v interface{}) (ok bool) {
		ks, vm := k.(string), v.(*manager)
		mp := vm.toMap()
		if vm.name == vm.tỹpe {
			viper.Set(ks, mp)
		} else {
			n := sm[vm.tỹpe]
			if n == nil {
				sm[vm.tỹpe] = []map[string]interface{}{mp}
			} else {
				sm[vm.tỹpe] = append(sm[vm.tỹpe], mp)
			}
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
