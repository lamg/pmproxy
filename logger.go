// Copyright © 2017-2019 Luis Ángel Méndez Gort

// This file is part of PMProxy.

// PMProxy is free software: you can redistribute it and/or
// modify it under the terms of the GNU Affero General
// Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your
// option) any later version.

// PMProxy is distributed in the hope that it will be
// useful, but WITHOUT ANY WARRANTY; without even the
// implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU Affero General Public
// License for more details.

// You should have received a copy of the GNU Affero General
// Public License along with PMProxy.  If not, see
// <https://www.gnu.org/licenses/>.

package pmproxy

import (
	"fmt"
	"log/syslog"
	h "net/http"
	"time"
)

type logger struct {
	sl *syslog.Writer
}

func newLogger(addr string) (l *logger, e error) {
	l = new(logger)
	if addr != "" {
		l.sl, e = syslog.Dial("tcp", addr, syslog.LOG_INFO,
			"")
	} else {
		l.sl, e = syslog.New(syslog.LOG_INFO, "")
	}
	return
}

func (l *logger) log(method, url, ip, user string,
	d time.Time) (e error) {
	// squid log format
	m := fmt.Sprintf(
		"%9d.000 %6d %s %s/%03d %d %s %s %s %s/%s %s",
		d.Unix(), 0, ip, "TCP_MISS", h.StatusOK, 0,
		method, url, user, "DIRECT", "-", "-")
	if e == nil {
		e = l.sl.Info(m)
	} else {
		e = l.sl.Alert(m)
	}
	return
}
