package pmproxy

import (
	"testing"

	rg "github.com/teambition/rrule-go"
)

func TestIntf(t *testing.T) {
	r := rg.NewRRule(rg.ROption{})
	r.Between
}
