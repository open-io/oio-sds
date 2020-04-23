// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

// An array of character considered as invalid hexadecimal.
// YOU SHOULD NOT alter this this unless you know what you are doing
var notHexa [256]bool

func init() {
	hexa := []byte{
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f',
		'A', 'B', 'C', 'D', 'E', 'F'}
	for i := 0; i < 256; i++ {
		notHexa[i] = true
	}
	for _, c := range hexa {
		notHexa[c] = false
	}
}

func isHexaString(name string, length int) bool {
	var i int
	var n rune
	for i, n = range name {
		if notHexa[byte(n)] {
			return false
		}
	}
	return length <= 0 || i+1 == length
}
