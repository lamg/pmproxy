package managers

type adDB struct {
	name string
	addr string
	suff string
	bdn  string
	user string
	pass string
	ldap *ld.Ldap
}

type keyVal struct {
	k, v string
}

func (d *adDB) fromMap(i interface{}) (e error) {
	addr, suff, bdn, user, pass :=
		keyVal{k: addrK}, keyVal{k: suffK}, keyVal{k: bdnK},
		keyVal{k: userK}, keyVal{k: passK}
	ks := []keyVal{addr, suff, bdn, user, pass}
	mp, e := cast.ToStringMapE(i)
	ib := func(i int) (b bool) {
		ks[i].v, e = cast.ToStringE(mp[ks[i].k])
		b = e != nil
		return
	}
	alg.BLnSrch(ib, len(ks))
	return
}

func (d *adDB) auth(user, pass string) (nuser string, e error) {
	nuser, e = d.ldap.AuthAndNorm(user, pass)
	return
}

func (d *adDB) userGroups(user string) (gs []string, e error) {
	mp, e := ldap.FullRecordAcc(user)
	if e == nil {
		gs, e = d.ldap.MembershipCNs(mp)
	}
	return
}

func (d *adDB) userName(user string) (name string, e error) {
	mp, e := ldap.FullRecordAcc(user)
	if e == nil {
		name, e = ldap.FullName(mp)
	}
	return
}

func (d *adDB) exec(c *Cmd) (term bool) {
	// TODO
	kf := []alg.KFunc{
		{
			authCmd, func() {},
		},
		{groupsCmd, func() {}},
		{nameCmd, func() {}},
	}
	alg.ExecF(kf, c.Cmd)
	return
}
