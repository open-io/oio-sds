// OpenIO SDS Go rawx
// Copyright (C) 2015-2019 OpenIO SAS
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

/*
Wraps the file repository to add chunk-related handlings, e.g. transparent compression,
alternative file names, etc.
*/

import (
	"os"
)

type chunkRepository struct {
	sub fileRepository
}

func (chunkrepo *chunkRepository) lock(ns, url string) error {
	return chunkrepo.sub.lock(ns, url)
}

func (chunkrepo *chunkRepository) has(name string) (bool, error) {
	v, _ := chunkrepo.sub.has(name)
	return v, nil
}

func (chunkrepo *chunkRepository) del(name string) error {
	err := chunkrepo.sub.del(name)
	if err == nil {
		return nil
	} else if err != os.ErrNotExist && !os.IsNotExist(err) {
		return err
	} else {
		return os.ErrNotExist
	}
}

func (chunkrepo *chunkRepository) get(name string) (fileReader, error) {
	r, err := chunkrepo.sub.get(name)
	if err == nil {
		return r, nil
	} else if err != os.ErrNotExist && !os.IsNotExist(err) {
		return nil, err
	} else {
		return nil, os.ErrNotExist
	}
}

func (chunkrepo *chunkRepository) put(name string) (fileWriter, error) {
	return chunkrepo.sub.put(name)
}

func (chunkrepo *chunkRepository) link(fromName,
	toName string) (fileWriter, error) {
	return chunkrepo.sub.link(fromName, toName)
}
