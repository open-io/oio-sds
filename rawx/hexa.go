// OpenIO SDS Go rawx
// Copyright (C) 2015-2018 OpenIO SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
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

var (
	accepted [32]byte
)

func init() {
	for i := 0; i < 32; i++ {
		accepted[i] = 0
	}
	hexa := []byte{
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'A', 'B', 'C', 'D', 'E', 'F'}
	for _, c := range hexa {
		accepted[c/8] |= (1 << (c % 8))
	}
}

func isValidString(name string, length int) bool {
	var i int
	var n rune
	for i, n = range name {
		if !isValidChar(byte(n)) {
			return false
		}
	}
	if length > 0 && i+1 != length {
		return false
	}
	return true
}

func isValidChar(b byte) bool {
	return 0 != (accepted[b/8] & (1 << (b % 8)))
}
