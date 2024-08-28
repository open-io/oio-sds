// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2022-2024 OVH SAS
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

/*
Wraps the file repository to add chunk-related handlings, e.g. transparent compression,
alternative file names, etc.
*/

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"openio-sds/rawx/hierarchy"
)

// Barely useful to intercept errors and mangle them.
type chunkRepository struct {
	recent  fileRepository
	archive fileRepository
}

func NewChunkRepository(basedir string, configuration RepositoryConfiguration) (*chunkRepository, error) {
	basedir = filepath.Clean(basedir)
	if !filepath.IsAbs(basedir) {
		return nil, errors.New("Filerepo path must be absolute")
	}

	repo := &chunkRepository{}
	repo.archive.root = basedir
	repo.archive.RepositoryConfiguration = configuration

	repo.recent.root = basedir + "/recent"
	repo.recent.RepositoryConfiguration = configuration
	repo.recent.RepositoryConfiguration.hashDepth = 1
	repo.recent.RepositoryConfiguration.hashWidth = 1

	if err := repo.archive.init(); err != nil {
		return nil, err
	}
	if err := repo.recent.init(); err != nil {
		return nil, err
	}

	return repo, nil
}

func (cr *chunkRepository) Archive(name string) error {
	locRecent := cr.recent.Locate(name)
	locArchive := cr.archive.Locate(name)

	if err := locRecent.Access(syscall.F_OK); err != nil {
		return err
	} else {
		err = locRecent.RenameTo(locArchive)
		if err == nil {
			return nil
		}
		if enoent(err) {
			err = os.MkdirAll(filepath.Join(locArchive.PathParentAbs, name), hierarchy.DirCreateMode)
			if err == nil {
				err = locRecent.RenameTo(locArchive)
			}
		}
		return err
	}
}

func (cr *chunkRepository) getAttr(name, key string, value []byte) (int, error) {
	return cr.archive.Locate(name).Getattr(key, value)
}

func (cr *chunkRepository) lock(ns, url string) error {
	return cr.archive.lock(ns, url)
}

func (cr *chunkRepository) del(name string) error {
	err := cr.archive.del(name)
	if err == nil {
		return nil
	} else if !enoent(err) {
		return err
	} else {
		return cr.recent.del(name)
		return os.ErrNotExist
	}
}

func enoent(err error) bool {
	if err == nil {
		return false
	}
	return err == os.ErrNotExist || os.IsNotExist(err)
}

func (cr *chunkRepository) get(name string) (fileReader, error) {
	// Try first in the archives
	r, err := cr.archive.get(name)

	if err == nil {
		return r, nil
	} else if !enoent(err) {
		return nil, err
	} else {
		// Not found in the archives, then fallback in the recent pool
		r, err = cr.recent.get(name)
		if err == nil {
			return r, nil
		} else if !enoent(err) {
			return nil, err
		} else {
			return nil, os.ErrNotExist
		}
	}
}

func (cr *chunkRepository) check(name string) bool {
	return cr.archive.check(name) || cr.recent.check(name)
}

func (cr *chunkRepository) put(name string) (fileWriter, error) {
	return cr.recent.put(name)
}

func (cr *chunkRepository) post(name string) fileUpdater {
	return cr.archive.post(name)
}

func (cr *chunkRepository) link(fromName, toName string) (linkOperation, error) {
	op, err := cr.archive.link(fromName, toName)
	if err == nil || !enoent(err) {
		return op, err
	}
	return cr.recent.link(fromName, toName)
}

func (cr *chunkRepository) symlinkNonOptimal(name string) error {
	return cr.archive.createSymlinkNonOptimal(name)
}
