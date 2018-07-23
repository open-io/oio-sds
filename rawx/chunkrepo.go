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
Wraps the sile repository to add chunk-related handlings, e.g. transparent compression,
alternative file names, etc.
*/

import (
	"os"
	"strings"
)

type chunkRepository struct {
	sub      Repository
	accepted [32]byte
}

func MakeChunkRepository(sub Repository) *chunkRepository {
	if sub == nil {
		panic("BUG : bad repository initiation")
	}
	r := new(chunkRepository)
	r.sub = sub

	return r
}

func (self *chunkRepository) Lock(ns, url string) error {
	return self.sub.Lock(ns, url)
}

func (self *chunkRepository) Has(name string) (bool, error) {
	if name, err := validateChunkName(name); err != nil {
		return false, err
	} else {
		v, _ := self.sub.Has(name)
		return v, nil
	}
}

func (self *chunkRepository) Del(name string) error {
	if name, err := validateChunkName(name); err != nil {
		return err
	} else {
		err = self.sub.Del(name)
		if err == nil {
			return nil
		} else if err != os.ErrNotExist && !os.IsNotExist(err) {
			return err
		} else {
			return os.ErrNotExist
		}
	}
}

func (self *chunkRepository) Get(name string) (FileReader, error) {
	if name, err := validateChunkName(name); err != nil {
		return nil, err
	} else {
		r, err := self.sub.Get(name)
		if err == nil {
			return r, nil
		} else if err != os.ErrNotExist && !os.IsNotExist(err) {
			return nil, err
		} else {
			return nil, os.ErrNotExist
		}
	}
}

func (self *chunkRepository) Put(name string) (FileWriter, error) {
	if name, err := validateChunkName(name); err != nil {
		return nil, err
	} else {
		w, err := self.sub.Put(name)
		if err == nil {
			return w, nil
		} else if err != os.ErrNotExist {
			return nil, err
		} else {
			return nil, os.ErrNotExist
		}
	}
}

func (self *chunkRepository) List(marker, prefix string, max int) (ListSlice, error) {
	if len(marker) > 0 && !isValidString(marker, 0) {
		out := ListSlice{make([]string, 0), false}
		return out, ErrListMarker
	}
	if len(prefix) > 0 && !isValidString(prefix, 0) {
		out := ListSlice{make([]string, 0), false}
		return out, ErrListPrefix
	}
	return self.sub.List(marker, prefix, max)
}

// Validate the return a canonic form the of name of the chunk.
func validateChunkName(name string) (string, error) {
	name = strings.ToUpper(name)
	if !isValidString(name, 64) {
		return "", ErrInvalidChunkName
	} else {
		return name, nil
	}
}
