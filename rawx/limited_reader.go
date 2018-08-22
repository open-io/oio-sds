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

import (
	"io"
)

type limitedReader struct {
	sub       io.Reader
	remaining int64
}

func (reader *limitedReader) Read(p []byte) (int, error) {

	if reader.remaining <= 0 {
		return 0, io.EOF
	}

	var n int
	var err error

	// Determine the max numer of bytes that can be read
	if int64(len(p)) > reader.remaining {
		l := int(reader.remaining)
		buf := make([]byte, l, l)
		n, err = reader.sub.Read(buf)
		if err == nil {
			copy(p, buf)
		}
	} else {
		n, err = reader.sub.Read(p)
	}

	if err == io.EOF && reader.remaining > 0 {
		err = ErrRangeNotSatisfiable
	} else if err == nil {
		reader.remaining = reader.remaining - int64(n)
	}
	return n, err
}

func (reader *limitedReader) Close() error {
	return nil
}
