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

/*
Minimal interface to a file repository, where each file might have
some <key,value> properties.
*/

type Repository interface {
	Lock(ns, url string) error
	Has(name string) (bool, error)
	Get(name string) (FileReader, error)
	Put(name string) (FileWriter, error)
	Link(fromName, toName string) (FileWriter, error)
	Del(name string) error
	List(marker, prefix string, max int) (ListSlice, error)
}

type ListSlice struct {
	Items     []string
	Truncated bool
}

type FileReader interface {
	Size() int64
	Seek(int64) error
	Close() error
	Read([]byte) (int, error)
	GetAttr(n string) ([]byte, error)
}

type FileWriter interface {
	Seek(int64) error
	Commit() error
	Abort() error
	Write([]byte) (int, error)
	SetAttr(n string, v []byte) error
}
