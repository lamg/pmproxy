// adbk adds multiple files with blacklisted domains to
// an access exception list for pmproxy use
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"regexp"
	"strings"
)

func main() {
	var dir, accFl, excp string
	flag.StringVar(&accFl, "a", "", "access exceptions file")
	flag.StringVar(&dir, "d", "", "blacklist directory")
	flag.StringVar(&excp, "e", "", "exceptions")
	flag.Parse()

	excs := strings.Split(excp, ",")
	ds, e := blackDir(dir, excs)
	if e == nil && len(ds) != 0 {
		e = copyAppend(accFl, ds)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e.Error())
	}
}

func blackDir(dir string, excp []string) (ds []string, e error) {
	var fs []os.FileInfo
	fs, e = ioutil.ReadDir(dir)
	if e == nil {
		for i := 0; i != len(fs); i++ {
			c := false
			for j := 0; !c && j != len(excp); j++ {
				c = excp[j] == fs[i].Name()
			}
			if fs[i].IsDir() && !c {
				ds = append(ds, path.Join(dir, fs[i].Name(), "domains"))
			}
		}
	}
	return
}

func copyAppend(accF string, domFs []string) (e error) {
	var af io.ReadCloser
	af, e = os.Open(accF)
	var afc io.WriteCloser
	if e == nil {
		afc, e = os.Create("output-" + accF)
	}
	var w *bufio.Writer
	var r *bufio.Scanner
	if e == nil {
		r, w = bufio.NewScanner(af), bufio.NewWriter(afc)
		_, e = w.WriteString("[\n")
	}
	if e == nil {
		e = appendAccExcp(r, w)
		af.Close()
	}
	for i := 0; e == nil && i != len(domFs); i++ {
		var f io.ReadCloser
		f, e = os.Open(domFs[i])
		if e == nil {
			r = bufio.NewScanner(f)
			e = appendBlacklist(r, w)
			f.Close()
		}
	}
	if w != nil {
		w.Flush()
	}
	if afc != nil {
		afc.Close()
	}
	return
}

func appendAccExcp(r *bufio.Scanner, w *bufio.Writer) (e error) {
	excpRg := regexp.MustCompile("\\{.+\\}")
	first := true
	for r.Scan() && e == nil {
		n := r.Text()
		s := excpRg.FindString(n)
		if s != "" {
			if first {
				_, e = w.WriteString("\t" + s)
				first = false
			} else {
				_, e = w.WriteString(",\n\t" + s)
			}
		}
	}
	return
}

func appendBlacklist(r *bufio.Scanner, w *bufio.Writer) (e error) {
	for r.Scan() && e == nil {
		n := r.Text()
		s := blackHost(n)
		_, e = w.WriteString(",\n\t" + s)
	}
	if e == nil {
		_, e = w.WriteString("\n]")
	}
	return
}

func blackHost(n string) (s string) {
	s = strings.Replace(n, ".", "\\.", -1)
	s += "$"
	s = fmt.Sprintf(
		`{"hostRE":"%s","start":null,"end":null,"consCfc":-1}`,
		n,
	)
	return
}
