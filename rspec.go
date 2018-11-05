package pmproxy

import (
	"encoding/json"
	"fmt"
	"net"
	h "net/http"
	"regexp"
	"strconv"
	"time"

	rt "github.com/lamg/rtimespan"
)

type simpleRSpec struct {
	rules [][]Rule
}

type Rule struct {
	Unit bool
	URLM *regexp.Regexp
	span *rt.RSpan
	IPM  IPMatcher
	Spec *Spec
}

type IPMatcher interface {
	Match(string) bool
}

func (s *simpleRSpec) Spec(t time.Time,
	r *h.Request) (n *Spec, e error) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	for _, j := range s.rules {
		b, k := true, 0
		for b && k != len(j) {
			b = j[k].Unit == ((j[k].IPM == nil || j[k].IPM.Match(ip)) &&
				(j[k].URLM == nil || j[k].URLM.MatchString(r.RequestURI)) &&
				(j[k].span == nil || j[k].span.ContainsTime(t)))
			k = k + 1
		}
		// b = all rules in j match the parameters
		if b {
			n = new(Spec)
			// add Spec to n
			sn := j[k].Spec
			if sn.Cr != nil {
				n.Cr = append(n.Cr, sn.Cr...)
			}
			if sn.Iface != "" {
				n.Iface = sn.Iface
			}
			if sn.ProxyURL != "" {
				n.ProxyURL = sn.ProxyURL
			}
		}
	}
	if len(n.Cr) == 0 || ((n.Iface == "") == (n.ProxyURL == "")) {
		e = InvalidSpec()
	}
	return
}

func InvalidSpec() (e error) {
	e = fmt.Errorf("Invalid Spec")
	return
}

func (s *simpleRSpec) Exec(cmd *AdmCmd) (r string, e error) {
	// TODO
	ids, i := make([]int, 2), 0
	if len(cmd.Args) < len(ids) {
		e = InvalidArgsLen(len(cmd.Args))
	}
	for e == nil && i != len(ids) {
		ids[i], e = strconv.Atoi(cmd.Args[i])
		if e == nil {
			i = i + 1
		}
	}
	// indexes parsed
	if e == nil {
		switch cmd.Cmd {
		case "add":
			rule := new(Rule)
			e = json.Unmarshal([]byte(cmd.Args[i+1]), rule)
			if e == nil {

			}
			if i == 2 {
				// index object
			} else if i == 3 {
				// index index object

			} else {

			}
			// TODO definir un formato de la regla en los argumentos
		case "del":
			// delete rule by index
			if i <= 2 {
				s.removeRule(ids, i)
			} else {
				e = InvalidArgsLen(i)
			}
		}
	}
	return
}

func InvalidArgsLen(n int) (e error) {
	e = fmt.Errorf("Invalid arguments length %d", n)
	return
}

func (s *simpleRSpec) removeRule(args []int, argc int) (e error) {
	if argc < len(s.rules) {
		if argc == 1 {
			s.rules = append(s.rules[:args[0]],
				s.rules[args[0]+1:]...)
			// no index out of range
		} else if argc == 2 {
			s.rules[args[0]] = append(s.rules[args[0]][:args[1]],
				s.rules[args[0]][args[1]+1:]...)
		} else {
			e = InvalidArgsLen(argc)
		}
	} else {
		e = IndexOutOfRange(argc, len(s.rules))
	}
	return
}

func IndexOutOfRange(i, n int) (e error) {
	e = fmt.Errorf("Index %d out of range %d", i, n)
	return
}
