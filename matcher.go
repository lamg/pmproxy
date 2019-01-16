package pmproxy

type matcher func(string) bool

func idMatch(s string) (b bool) {
	b = true
	return
}

func negMatch(s string) (b bool) {
	b = false
	return
}
