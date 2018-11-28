package pmproxy

import (
	"sync"

	ld "github.com/lamg/ldaputil"
)

type groupIPM struct {
	NameF  string `json:"name" toml:"name"`
	Group  string `toml: "group"`
	IPUser string `toml: "ipUser"`
	ipUser IPUser
	ldap   *ld.Ldap
	cache  *sync.Map
}

func (g *groupIPM) Match(ip string) (ok bool) {
	user := g.ipUser.User(ip)
	ok = user != ""
	var gs []string
	if ok {
		gs = g.getOrUpdate(user)
		ok = gs != nil
	}
	if ok {
		i, match := 0, false
		for !match && i != len(gs) {
			match, i = gs[i] == g.Group, i+1
		}
		ok = match
	}
	return
}

func (g *groupIPM) getOrUpdate(user string) (groups []string) {
	gs, ok := g.cache.Load(user)
	if !ok {
		rec, e := g.ldap.FullRecordAcc(user)
		if e == nil {
			groups, e = g.ldap.MembershipCNs(rec)
		}
		if e == nil {
			g.cache.Store(user, groups)
		}
		if e != nil {
			groups = nil
		}
	} else {
		groups = gs.([]string)
	}
	return
}

func (g *groupIPM) clearCache(user string) {
	g.cache.Delete(user)
}

func (g *groupIPM) Exec(cmd *AdmCmd) (r string, e error) {
	return
}

func (g *groupIPM) Name() (r string) {
	r = g.NameF
	return
}
