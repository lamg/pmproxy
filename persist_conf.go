package pmproxy

import (
	"github.com/BurntSushi/toml"
	"io"
)

func (c *config) persist(w io.Writer) (e error) {
	n := toml.NewEncoder(w)
	// TODO
	e = n.Encode(c)
	return
}
