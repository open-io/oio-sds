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
	"crypto/md5"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	syscall "golang.org/x/sys/unix"
)

const (
	openFlagsReadOnly  int = syscall.O_RDONLY | syscall.O_NOATIME | syscall.O_CLOEXEC
	openFlagsWriteOnly int = syscall.O_WRONLY | syscall.O_CREAT | syscall.O_EXCL | syscall.O_NOATIME | syscall.O_CLOEXEC
	openFlagsSyncDir   int = syscall.O_DIRECTORY | syscall.O_RDWR | syscall.O_NOATIME
	openFlagsSyncFile  int = syscall.O_RDONLY | syscall.O_NOATIME | syscall.O_CLOEXEC
	openFlagsLink      int = syscall.O_WRONLY | syscall.O_NOATIME | syscall.O_CLOEXEC
	openFlagsBasedir   int = syscall.O_DIRECTORY | syscall.O_RDONLY | syscall.O_NOATIME | syscall.O_PATH
)

type fileRepository struct {
	root            string
	rootFd          int
	putOpenMode     uint32
	putMkdirMode    os.FileMode
	hashWidth       int
	hashDepth       int
	syncFile        bool
	syncDir         bool
	fallocateFile   bool
	fadviseUpload   int
	fadviseDownload int
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
	fr.syncFile = configDefaultSyncFile
	fr.syncDir = configDefaultSyncDir
	fr.fallocateFile = configDefaultFallocate
	fr.fadviseUpload = configDefaultFadviseUpload
	fr.fadviseDownload = configDefaultFadviseDownload

	flags := openFlagsBasedir
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
	relPath := fr.nameToRelPath(name)
	absPath := fr.root + "/" + relPath
	xattrName := AttrNameFullPrefix + name

	var err error
	err = syscall.Removexattr(absPath, xattrName)
	if err != nil {
		LogWarning("Failed to remove xattr %s on %s: %s", xattrName, absPath, err.Error())
		err = nil
	}
	err = syscall.Unlinkat(fr.rootFd, relPath, 0)
	if err != nil && fr.syncDir {
		LogWarning("Failed to remove chunk (was %s) %s: %s", xattrName, absPath, err.Error())
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

	f := &realFileReader{f: os.NewFile(uintptr(fd), path), repo: fr}

	switch fr.fadviseUpload {
	case configFadviseNone:
	case configFadviseNoReuse:
		syscall.Fadvise(fd, 0, f.size(), syscall.FADV_DONTNEED)
	case configFadviseReuse:
		syscall.Fadvise(fd, 0, f.size(), syscall.FADV_SEQUENTIAL)
	}

	return f, nil
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
		_ = syscall.Unlinkat(fr.rootFd, pathTemp, 0)
		_ = syscall.Close(fd)
		return nil, os.ErrExist
	}

	return &realFileWriter{
		fd: fd, pathFinal: path, pathTemp: pathTemp, repo: fr,
		allocated: 0, written: 0}, nil
}

func (fr *fileRepository) put(name string) (fileWriter, error) {
	path := fr.nameToRelPath(name)
	return fr.putRelPath(path)
}

// Fast path: initial optimistic attempt when everythng works fine
// (i.e. when the source exists and the target directory exists).
func (fr *fileRepository) linkRelPath_FastPath(fromPath, toPath string) (linkOperation, error) {
	pathTemp := toPath + ".pending"

	err := syscall.Linkat(fr.rootFd, fromPath, fr.rootFd, pathTemp, 0)
	if err != nil {
		return nil, err
	}

	defer func() { _ = syscall.Unlinkat(fr.rootFd, pathTemp, 0) }()
	err = syscall.Linkat(fr.rootFd, fromPath, fr.rootFd, toPath, 0)
	if err != nil {
		return nil, err
	}

	return &realLinkOp{relPath: toPath, repo: fr}, nil
}

func (fr *fileRepository) linkRelPath(fromPath, toPath string) (linkOperation, error) {
	for {
		op, err := fr.linkRelPath_FastPath(fromPath, toPath)
		if err == nil {
			return op, err
		}

		switch err.(syscall.Errno) {
		case syscall.ENOENT:
			if e0 := syscall.Faccessat(fr.rootFd, fromPath, syscall.F_OK, 0); e0 != nil {
				return nil, err
			}
			if e0 := os.MkdirAll(filepath.Dir(toPath), fr.putMkdirMode); e0 != nil {
				return nil, err
			}
		default:
			// The initial link() failed
			return nil, err
		}
	}
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
	err := syscall.Unlinkat(lo.repo.rootFd, lo.relPath, 0)
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

	allocated int64
	written   int64
}

func (fw *realFileWriter) setAttr(key string, value []byte) error {
	return syscall.Fsetxattr(fw.fd, key, value, 0)
}

func (fw *realFileWriter) Write(buffer []byte) (int, error) {
	buflen := int64(len(buffer))

	if fw.written+buflen > fw.allocated {
		fw.Extend(uploadExtensionSize)
	}

	fw.written += buflen
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
	return syscall.Unlinkat(fw.repo.rootFd, fw.pathTemp, 0)
}

func (fw *realFileWriter) commit() error {
	var err error

	if fw.allocated > fw.written {
		err = syscall.Ftruncate(fw.fd, fw.written)
	}

	if err == nil {
		switch fw.repo.fadviseUpload {
		case configFadviseNone:
		case configFadviseNoReuse:
			syscall.Fadvise(fw.fd, 0, fw.written, syscall.FADV_DONTNEED)
		case configFadviseReuse:
			syscall.Fadvise(fw.fd, 0, fw.written, syscall.FADV_SEQUENTIAL)
		}
	}

	if err == nil {
		err = fw.syncFile()
		if err == nil {
			err := syscall.Renameat(fw.repo.rootFd, fw.pathTemp, fw.repo.rootFd, fw.pathFinal)
			if err == nil {
				_ = fw.syncDir()
			}
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

func (fw *realFileWriter) Extend(size int64) {
	if fw.repo.fallocateFile {
		err := syscall.Fallocate(fw.fd, syscall.FALLOC_FL_KEEP_SIZE, fw.written, size)
		if err == nil {
			fw.allocated = fw.written + size
		}
	}
}

type realFileReader struct {
	f    *os.File
	repo *fileRepository
}

func (fr *realFileReader) size() int64 {
	fi, err := fr.f.Stat()
	if err != nil {
		return -1
	} else {
		return fi.Size()
	}
}

func (fr *realFileReader) seek(offset int64) error {
	_, err := fr.f.Seek(offset, os.SEEK_SET)
	return err
}

func (fr *realFileReader) Close() error {
	err := fr.f.Close()
	fr.f = nil
	return err
}

func (fr *realFileReader) Read(buffer []byte) (int, error) {
	return fr.f.Read(buffer)
}

func (fr *realFileReader) File() *os.File {
	return fr.f
}

func (fr *realFileReader) getAttr(key string, value []byte) (int, error) {
	return syscall.Fgetxattr(int(fr.f.Fd()), key, value)
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

func (fileReader *realFileReader) recomputeHash() (string, error) {
	h := md5.New()
	if _, err := io.Copy(h, fileReader.f); err != nil {
		return "", err
	}

	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), nil
}
