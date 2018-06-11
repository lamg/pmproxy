package main

import (
	"bufio"
	"flag"
	"io"
	"os"
	"regexp"
	"strings"

	pm "github.com/lamg/pmproxy"
)

func main() {
	var fls, accFl string
	flag.StringVar(&accFl, "a", "", "access exceptions file")
	flag.StringVar(&fls, "f", "",
		"blacklist files to add, comma separated")
	flag.Parse()

	files := strings.Split(fls, ",")
	if len(files) != 0 {

	}
}

func appendBlacklisted(acf string, bls []string) (e error) {
	var l []pm.AccExcp
	l, e = loadAccExcp(acf)
	for i := 0; e == nil && i != len(bls); i++ {
		readBlacklist(l, r)
	}
	return
}

func loadAccExcp(fl string) (l []pm.AccExcp, e error) {
	var r io.ReadCloser
	r, e = os.Open(fl)
	if e == nil {
		l, e = pm.ReadAccExcp(r)
		r.Close()
	}
	return
}

func readBlacklist(l []pm.AccExcp, r *bufio.Reader) (e error) {
	for e == nil {
		var n string
		n, e = r.ReadString('\n')
		if e == nil {
			hostR := escapeHost(n)
			if hostR != nil {
				a := pm.AccExcp{
					ConsCfc: -1,
					HostR:   hostR,
				}
				l = append(l, a)
			}
		}
	}
	if e == io.EOF {
		e = nil
	}
	return
}

func escapeHost(n string) (r *regexp.Regexp) {
	s := strings.Replace(n, ".", "\\.", -1)
	s += "$"
	r, _ = regexp.Compile(s)
	return
}
