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

package state

import (
	"bytes"
	"context"

	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

type State struct {
	db *leveldb.DB
}

func Open(path string) (*State, error) {
	opts := opt.Options{
		Compression: opt.DefaultCompression,
		Strict:      opt.NoStrict,
		NoSync:      true,
	}

	db, err := leveldb.OpenFile(path, &opts)
	if err != nil {
		return nil, err
	}
	return &State{db: db}, nil
}

func (s *State) Close() error {
	if s != nil {
		if s.db != nil {
			return s.db.Close()
		}
	}
	return nil
}

func (s *State) Insert(chunk string) error {
	kBuf := bytes.Buffer{}
	kBuf.WriteString(chunk)

	return s.db.Put(kBuf.Bytes(), []byte{0}, nil)
}

func (s *State) Delete(chunk string) error {
	kBuf := bytes.Buffer{}
	kBuf.WriteString(chunk)

	return s.db.Delete(kBuf.Bytes(), nil)
}

type Record struct {
	Chunk string
	Size  uint64
}

func (s *State) Scan(ctx context.Context, out chan Record) error {
	//start := util.Range{Start: []byte{}, Limit: []byte{'Z'}}
	opts := opt.ReadOptions{DontFillCache: true, Strict: opt.NoStrict}

	it := s.db.NewIterator(nil, &opts)
	for it.Next() && ctx.Err() == nil {
		k := string(it.Key())
		out <- Record{Chunk: k, Size: 0}
	}
	it.Release()
	return ctx.Err()
}
