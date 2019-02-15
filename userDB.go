package pmproxy

type auth func(string, string) (string, error)
type userGroup func(string) ([]string, error)
