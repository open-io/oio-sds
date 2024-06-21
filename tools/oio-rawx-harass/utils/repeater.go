// OpenIO SDS oio-rawx-harass
// Copyright (C) 2019-2020 OpenIO SAS
// Copyright (C) 2021-2024 OVH SAS
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

package utils

import (
	"io"
	"math/rand"
)

const (
	bufferSize int64 = 65536
)

var (
	buffer []byte
)

func init() {
	buffer = make([]byte, bufferSize)
	rand.Read(buffer)
}

type Repeater struct {
	remaining int64
}

func (r *Repeater) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}

	n := int64(len(p))
	if n > bufferSize {
		n = bufferSize
	}
	if n > r.remaining {
		n = r.remaining
	}

	copy(p, buffer[:n])
	r.remaining -= n
	return int(n), nil
}

func NewRepeater(size int64) io.Reader {
	return &Repeater{remaining: size}
}
