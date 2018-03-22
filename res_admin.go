package pmproxy

// ResAdm provides procedures to admnistrate the resource
// determinators PMProxy use
type ResAdm struct {
	Sms map[string]*SMng
	Cms map[string]*CMng
	Dms map[string]*DMng
	Cls map[string]*CLMng
}

// TODO implement JSON marshalers and unmarshaler for ever
// ResAdm field
