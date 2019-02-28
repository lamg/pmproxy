// Copyright © 2017-2019 Luis Ángel Méndez Gort

// This file is part of PMProxy.

// PMProxy is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.

// PMProxy is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Affero General Public
// License for more details.

// You should have received a copy of the GNU Affero General
// Public License along with PMProxy.  If not, see
// <https://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	h "net/http"
	"os"
)

func main() {
	h.DefaultTransport.(*h.Transport).TLSClientConfig =
		&tls.Config{InsecureSkipVerify: true}
	app := cli.NewApp()
	app.Commands = []cli.Command{
		{
			Name:    "login",
			Aliases: []string{"l"},
			Usage:   "Open a session in PMProxy server",
			Action: func(c *cli.Context) (e error) {
				args := c.Args()
				if len(args) == 3 {
					urls, user, pass := args[0], args[1], args[2]
					e = login(urls, user, pass)
				} else {
					e = fmt.Errorf("Need 3 arguments: PMProxy URL," +
						"user, and password")
				}
				return
			},
		},
	}
	e := app.Run(os.Args)
	if e != nil {
		log.Fatal(e)
	}
}

type cred struct {
	User string `json: "user"`
	Pass string `json: "pass"`
}

func login(urls, user, pass string) (e error) {
	var bs []byte
	var r *h.Response
	fs := []func(){
		func() {
			cr := &cred{User: user, Pass: pass}
			bs, e = json.Marshal(cr)
		},
		func() {
			buff := bytes.NewBuffer(bs)
			u := urls + "/api/auth"
			r, e = h.Post(u, "text/json", buff)
		},
		func() {
			bs, e = ioutil.ReadAll(r.Body)
			r.Body.Close()
		},
		func() {
			if r.StatusCode == h.StatusOK {
				e = ioutil.WriteFile("login.secret", bs, 0644)
			} else {
				e = fmt.Errorf("%s", string(bs))
			}
		},
	}
	trueFF(fs, func() bool { return e == nil })
	return
}

type intBool func(int) bool

// bLnSrch is the bounded lineal search algorithm
// { n ≥ 0 ∧ forall.n.(def.ib) }
// { i =⟨↑j: 0 ≤ j ≤ n ∧ ⟨∀k: 0 ≤ k < j: ¬ib.k⟩: j⟩
//   ∧ b ≡ i ≠ n }
func bLnSrch(ib intBool, n int) (b bool, i int) {
	b, i, udb := false, 0, true
	// udb: undefined b for i
	for !b && i != n {
		if udb {
			// udb ∧ i ≠ n
			b, udb = ib(i), false
		} else {
			// ¬udb ∧ ¬b
			i, udb = i+1, true
		}
	}
	return
}

// trueFF means true forall function
func trueFF(fs []func(), okf func() bool) (ok bool) {
	ok, _ = trueForall(func(i int) (b bool) {
		fs[i]()
		b = okf()
		return
	},
		len(fs),
	)
	return
}

func trueForall(ib intBool, n int) (ok bool, i int) {
	r, i := bLnSrch(
		func(i int) (b bool) {
			b = !ib(i)
			return
		},
		n,
	)
	// calculated showing that doesn't exists function
	// yielding false
	ok = !r
	return
}

type intF func(int)

func forall(inf intF, n int) {
	for i := 0; i != n; i++ {
		inf(i)
	}
}
