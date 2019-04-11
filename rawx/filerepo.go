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

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	hashWidth    = 3
	hashDepth    = 1
	putOpenMode  = 0644
	putMkdirMode = 0755
)

const (
	openFlagsReadOnly  int = syscall.O_RDONLY | syscall.O_NOATIME | syscall.O_CLOEXEC
	openFlagsWriteOnly int = syscall.O_WRONLY | syscall.O_CREAT | syscall.O_EXCL | syscall.O_NOATIME | syscall.O_CLOEXEC
	openFlagsSyncDir   int = syscall.O_DIRECTORY | syscall.O_RDWR | syscall.O_NOATIME
	openFlagsSyncFile  int = syscall.O_RDONLY | syscall.O_NOATIME | syscall.O_CLOEXEC
	openFlagsLink      int = syscall.O_WRONLY | syscall.O_NOATIME | syscall.O_CLOEXEC
)

type fileRepository struct {
	root          string
	rootFd        int
	putOpenMode   uint32
	putMkdirMode  os.FileMode
	hashWidth     int
	hashDepth     int
	syncFile      bool
	syncDir       bool
	fallocateFile bool
}

func (fr *fileRepository) init(root string) error {
	var err error
	basedir := filepath.Clean(root)
	if !filepath.IsAbs(basedir) {
		return errors.New("Filerepo path must be absolute")
	}
	fr.root = basedir
	fr.hashWidth = hashWidth
	fr.hashDepth = hashDepth
	fr.putOpenMode = putOpenMode
	fr.putMkdirMode = putMkdirMode
	fr.syncFile = false
	fr.syncDir = true

	flags := syscall.O_DIRECTORY | syscall.O_RDONLY | syscall.O_NOATIME
	if fr.rootFd, err = syscall.Open(fr.root, flags, 0); err != nil {
		return err
	}
	return nil
}

func (fr *fileRepository) getAttr(name, key string, value []byte) (int, error) {
	absPath := fr.root + "/" + fr.nameToRelPath(name)
	return syscall.Getxattr(absPath, key, value)
}

func (fr *fileRepository) lock(ns, id string) error {
	var err error
	err = setOrHasXattr(fr.root, "user.server.id", id)
	if err != nil {
		return err
	}
	err = setOrHasXattr(fr.root, "user.server.ns", ns)
	if err != nil {
		return err
	}
	err = setOrHasXattr(fr.root, "user.server.type", "rawx")
	if err != nil {
		return err
	}
	return nil
}

func (fr *fileRepository) del(name string) error {
	var err error
	relPath := fr.nameToRelPath(name)
	err = syscall.Removexattr(fr.root+"/"+relPath, AttrNameFullPrefix+name)
	if err != nil {
		LogWarning("Error to remove content fullpath: %s", err)
		err = nil
	}
	err = syscall.Unlinkat(fr.rootFd, relPath)
	if err != nil && fr.syncDir {
		dir := filepath.Dir(relPath)
		err = fr.syncRelDir(dir)
	}
	return err
}

func (fr *fileRepository) getRelPath(path string) (fileReader, error) {
	fd, err := syscall.Openat(fr.rootFd, path, openFlagsReadOnly, 0)
	if err != nil {
		return nil, err
	}
	return &realFileReader{fd: fd, path: path, repo: fr}, nil
}

func (fr *fileRepository) get(name string) (fileReader, error) {
	path := fr.nameToRelPath(name)
	return fr.getRelPath(path)
}

func (fr *fileRepository) putRelPath(path string) (fileWriter, error) {
	pathTemp := path + ".pending"
	fd, err := syscall.Openat(fr.rootFd, pathTemp, openFlagsWriteOnly, fr.putOpenMode)
	if err != nil {
		if os.IsNotExist(err) {
			// Lazy dir creation
			err = os.MkdirAll(filepath.Dir(fr.root+"/"+path), fr.putMkdirMode)
			if err == nil {
				return fr.putRelPath(path)
			}
		}
		return nil, err
	}

	// Check that the final chunk doesn't exist yet
	err = syscall.Faccessat(fr.rootFd, path, syscall.F_OK, 0)
	if err == nil {
		_ = syscall.Unlinkat(fr.rootFd, pathTemp)
		_ = syscall.Close(fd)
		return nil, os.ErrExist
	}

	return &realFileWriter{
		fd:        fd,
		pathFinal: path, pathTemp: pathTemp, repo: fr}, nil
}

func (fr *fileRepository) put(name string) (fileWriter, error) {
	path := fr.nameToRelPath(name)
	return fr.putRelPath(path)
}

func (fr *fileRepository) linkRelPath(fromPath, toPath string) (linkOperation, error) {
	var err error
	pathTemp := toPath + ".pending"

	absSrc := fr.root + "/" + fromPath
	absTemp := fr.root + "/" + pathTemp
	absFinal := fr.root + "/" + toPath

	// TODO(jfs): improve with Linkat
	err = os.Link(absSrc, absTemp)
	if err == nil {
		defer func() { _ = syscall.Unlinkat(fr.rootFd, absTemp) }()
		// TODO(jfs): improve with Linkat
		err = os.Link(absSrc, absFinal)
		if err == nil {
			return &realLinkOp{relPath: toPath, repo: fr}, nil
		}
	}

	if os.IsNotExist(err) {
		err = os.MkdirAll(filepath.Dir(toPath), fr.putMkdirMode)
		if err != nil {
			return nil, err
		} else {
			return fr.linkRelPath(fromPath, toPath)
		}
	}

	return nil, err
}

func (fr *fileRepository) link(src, dst string) (linkOperation, error) {
	relSrc := fr.nameToRelPath(src)
	relDst := fr.nameToRelPath(dst)
	return fr.linkRelPath(relSrc, relDst)
}

// Synchronize the directory, based on its path
func (fr *fileRepository) syncRelDir(relPath string) error {
	fd, err := syscall.Openat(fr.rootFd, relPath, openFlagsSyncDir, 0)
	if err == nil {
		err = syscall.Fdatasync(fd)
		syscall.Close(fd)
		fd = -1
	}
	return err
}

// Synchronize just the file, based on its path
func (fr *fileRepository) syncRelFile(relPath string) error {
	fd, err := syscall.Openat(fr.rootFd, relPath, openFlagsSyncFile, 0)
	if err == nil {
		err = syscall.Fdatasync(fd)
		syscall.Close(fd)
		fd = -1
	}
	return err
}

type realLinkOp struct {
	relPath string
	repo    *fileRepository
}

func (lo *realLinkOp) setAttr(key string, value []byte) error {
	return syscall.Setxattr(lo.repo.root+"/"+lo.relPath, key, value, 0)
}

func (lo *realLinkOp) commit() error {
	var err error
	if lo.repo.syncDir {
		err = lo.repo.syncRelDir(filepath.Dir(lo.relPath))
	}
	if lo.repo.syncFile {
		err = lo.repo.syncRelFile(lo.relPath)
	}
	return err
}

func (lo *realLinkOp) rollback() error {
	err := syscall.Unlinkat(lo.repo.rootFd, lo.relPath)
	if err == nil && lo.repo.syncDir {
		err = lo.repo.syncRelDir(filepath.Dir(lo.relPath))
	}
	return err
}

type realFileWriter struct {
	fd        int
	pathFinal string
	pathTemp  string
	repo      *fileRepository
}

func (fw *realFileWriter) seek(offset int64) error {
	_, err := syscall.Seek(fw.fd, offset, os.SEEK_SET)
	return err
}

func (fw *realFileWriter) setAttr(key string, value []byte) error {
	return syscall.Setxattr(fw.repo.root+"/"+fw.pathTemp, key, value, 0)
}

func (fw *realFileWriter) Write(buffer []byte) (int, error) {
	return syscall.Write(fw.fd, buffer)
}

func (fw *realFileWriter) close() {
	if fw.fd >= 0 {
		fd := fw.fd
		fw.fd = -1
		_ = syscall.Close(fd)
	}
}

func (fw *realFileWriter) abort() error {
	defer fw.close()
	return syscall.Unlinkat(fw.repo.rootFd, fw.pathTemp)
}

func (fw *realFileWriter) commit() error {
	err := fw.syncFile()
	if err == nil {
		err := syscall.Renameat(fw.repo.rootFd, fw.pathTemp, fw.repo.rootFd, fw.pathFinal)
		if err == nil {
			_ = fw.syncDir()
		}
	}

	if err != nil {
		fw.abort()
	} else {
		fw.close()
	}
	return err
}

func (fw *realFileWriter) syncFile() error {
	if !fw.repo.syncFile {
		return nil
	}
	return syscall.Fdatasync(fw.fd)
}

func (fw *realFileWriter) syncDir() error {
	if !fw.repo.syncDir {
		return nil
	}
	dir := filepath.Dir(fw.pathFinal)
	return fw.repo.syncRelDir(dir)
}

type realFileReader struct {
	fd   int
	stat syscall.Stat_t
	path string
	repo *fileRepository
}

func (fr *realFileReader) size() int64 {
	if fr.stat.Ino == 0 {
		err := syscall.Fstat(fr.fd, &fr.stat)
		if err != nil {
			return -1
		}
	}
	return fr.stat.Size
}

func (fr *realFileReader) seek(offset int64) error {
	_, err := syscall.Seek(fr.fd, offset, os.SEEK_SET)
	return err
}

func (fr *realFileReader) Close() error {
	if err := syscall.Close(fr.fd); err != nil {
		return err
	} else {
		fr.fd = -1
		return nil
	}
}

func (fr *realFileReader) Read(buffer []byte) (int, error) {
	n, err := syscall.Read(fr.fd, buffer)
	if err != nil {
		return n, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return n, err
}

func (fr *realFileReader) getAttr(key string, value []byte) (int, error) {
	return syscall.Getxattr(fr.repo.root+"/"+fr.path, key, value)
}

func (fr *fileRepository) nameToRelPath(name string) string {
	var result strings.Builder
	for i := 0; i < fr.hashDepth; i++ {
		start := i * fr.hashDepth
		result.WriteString(name[start : start+fr.hashWidth])
		result.WriteRune('/')
	}
	result.WriteString(name)
	return result.String()
}

func setOrHasXattr(path, key, value string) error {
	if err := syscall.Setxattr(path, key, []byte(value), 1); err == nil {
		return nil
	} else if !os.IsExist(err) {
		return err
	}
	tab := make([]byte, 256)
	sz, err := syscall.Getxattr(path, key, tab)
	if err != nil {
		return err
	}
	if bytes.Equal([]byte(value), tab[:sz]) {
		return nil
	}
	return errors.New("XATTR mismatch")
}
