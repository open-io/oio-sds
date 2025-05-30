// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2021-2025 OVH SAS
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
	"io"
	"os"
	"time"
)

type decorable interface {
	setAttr(n string, v []byte) error
}

type fileReader interface {
	io.ReadCloser

	// Return the underlying os.File
	File() *os.File

	mtime() time.Time
	size() int64
	seek(int64) error
	getAttr(key string, value []byte) (int, error)
	listAttr(value []byte) (int, error)
}

type fileWriter interface {
	decorable

	// Prepare a placeholder for the file, if the underlying implementation allows it.
	Extend(size int64)

	Write([]byte) (int, error)

	commit() error
	abort() error
}

type linkOperation interface {
	decorable
	commit() error
	rollback() error
}

type fileUpdater interface {
	decorable
}
