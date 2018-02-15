package pmproxy

import (
	"strings"
	"unicode"

	"golang.org/x/text/secure/precis"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

func myLower(s string) (r string) {
	// code from https://stackoverflow.com/questi
	// ons/26722450/remove-diacritics-using-go
	lc := precis.NewIdentifier(
		precis.AdditionalMapping(func() transform.Transformer {
			return transform.Chain(norm.NFD, transform.RemoveFunc(func(r rune) bool {
				return unicode.Is(unicode.Mn, r)
			}))
		}),
		precis.Norm(norm.NFC),
		// This is the default; be explicit though.
	)
	p, _ := lc.String(s)
	r = strings.ToLower(p)
	return
}
