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

// consR stands for consumption restrictor,
// it restricts several aspects of a connection
type consR struct {
	open   func(string) bool
	can    func(string, int) bool
	update func(string, int)
	close  func(string)
}

func idConsR() (c *consR) {
	c = &consR{
		open: func(ip string) (ok bool) {
			ok = true
			return
		},
		can: func(ip string, down int) (ok bool) {
			ok = true
			return
		},
		update: func(ip string, down int) {},
		close:  func(ip string) {},
	}
	return
}

func negConsR() (c *consR) {
	c = &consR{
		open: func(ip string) (ok bool) {
			ok = false
			return
		},
		can: func(ip string, down int) (ok bool) {
			ok = false
			return
		},
		update: func(ip string, down int) {},
		close:  func(ip string) {},
	}
	return
}
