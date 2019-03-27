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
	"crypto/tls"
	"github.com/lamg/pmproxy"
	"github.com/urfave/cli"
	"log"
	h "net/http"
	"os"
)

func main() {
	h.DefaultTransport.(*h.Transport).TLSClientConfig =
		&tls.Config{InsecureSkipVerify: true}
	app := cli.NewApp()
	app.Commands = []cli.Command{
		pmproxy.Discover(),
		pmproxy.Login(),
		pmproxy.Logout(),
		pmproxy.UserStatus(),
		pmproxy.ResetConsumption(),
	}
	e := app.Run(os.Args)
	if e != nil {
		log.Fatal(e)
	}
}
