package main

import (
	"encoding/json"
	"github.com/lamg/pmproxy"
	"github.com/urfave/cli"
	fh "github.com/valyala/fasthttp"
	"log"
	"os"
)

func main() {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "s",
			Usage: "PMProxy server",
		},
	}
	app.Commands = []cli.Command{
		{
			Name: "login",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "u",
					Usage: "User name",
				},
				cli.StringFlag{
					Name:  "p",
					Usage: "Password",
				},
			},
			Action: login,
		},
	}

	e := app.Run(os.Args)
	if e != nil {
		log.Fatal(e)
	}
}

func login(c *cli.Context) (e error) {
	cmd := &pmproxy.AdmCmd{
		Cmd:     "open",
		Manager: "sm",
		User:    c.String("u"),
		Pass:    c.String("p"),
	}
	var bs []byte
	bs, e = json.Marshal(cmd)
	fh.Post(bs, c.String("s"), nil)
	return
}
