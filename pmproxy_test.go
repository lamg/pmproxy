package pmproxy

import (
	h "net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDial(t *testing.T) {
	ts := []struct {
		addr string
		body string
		err  bool
	}{}

}
