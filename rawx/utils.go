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
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"math/rand"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Hexadecimal characters
const hexaCharacters = "0123456789ABCDEF"

// An array of character considered as invalid hexadecimal.
// YOU SHOULD NOT alter this this unless you know what you are doing
var notHexa [256]bool

func init() {
	rand.Seed(time.Now().UnixNano())

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

func isHexaString(name string, minLen int, maxLen int) bool {
	var i int
	var n rune
	for i, n = range name {
		if notHexa[byte(n)] {
			return false
		}
	}
	return i+1 >= minLen && i < maxLen
}

func hasPrefix(s, prefix string) (string, bool) {
	if strings.HasPrefix(s, prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

func _dslash(s string) bool { return len(s) > 1 && s[0] == '/' && s[1] == '/' }
func itoa(i int) string     { return strconv.Itoa(i) }
func utoa(i uint64) string  { return strconv.FormatUint(i, 10) }
func itoa64(i int64) string { return strconv.FormatInt(i, 10) }

type PeriodicThrottle struct {
	nanoLast int64
	period   int64
}

func (pt *PeriodicThrottle) Ok() bool {
	nanoNow := time.Now().UnixNano()
	nanoThen := pt.nanoLast
	if nanoThen == 0 || nanoNow-nanoThen > pt.period {
		return atomic.CompareAndSwapInt64(&pt.nanoLast, nanoThen, nanoNow)
	}
	return false
}

func randomString(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
