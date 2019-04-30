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
	"github.com/lamg/pmproxy/client"
	"github.com/spf13/afero"
	"github.com/urfave/cli"
	"log"
	"os"
)

func main() {
	cl := client.PMClient{
		Fs:      afero.NewOsFs(),
		PostCmd: client.PostCmd,
	}
	app := cli.NewApp()
	app.Commands = []cli.Command{
		cl.Discover(),
		cl.Login(),
		cl.Logout(),
		cl.LoggedUsers(),
		cl.UserStatus(),
		cl.ResetConsumption(),
		cl.ShowMng(),
	}
	e := app.Run(os.Args)
	if e != nil {
		log.Fatal(e)
	}
}
