package pmproxy

// MtIface associates a *ReqMatcher with a network
// interface name
type MtIface struct {
	Predicate `json:"resM"`
	Iface     string `json:"iface"`
}

// IMng manages interfaces
type IMng []MtIface
