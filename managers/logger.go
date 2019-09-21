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

package managers

import (
	"fmt"
	"log/syslog"
	h "net/http"
	"time"
)

type logger struct {
	addr   string
	writer *syslog.Writer
}

func newLogger(addr string) (l *logger, e error) {
	l = &logger{addr: addr}
	if addr != "" {
		l.writer, e = syslog.Dial("tcp", addr, syslog.LOG_INFO,
			"")
	} else {
		l.writer, e = syslog.New(syslog.LOG_INFO, "")
	}
	return
}

func (l *logger) log(method, url, ip, user string,
	d time.Time) (e error) {
	// squid log format
	_, e = fmt.Fprintf(l.writer,
		"%9d.000 %6d %s %s/%03d %d %s %s %s %s/%s %s",
		d.Unix(), 0, ip, "TCP_MISS", h.StatusOK, 0,
		method, url, user, "DIRECT", "-", "-")
	return
}

func (l *logger) warning(message string) (e error) {
	e = l.writer.Warning(message)
	return
}
