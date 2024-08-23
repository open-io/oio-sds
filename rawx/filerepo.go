// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2021-2024 OVH SAS
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
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	syscall "golang.org/x/sys/unix"
	"openio-sds/rawx/defs"
	"openio-sds/rawx/hierarchy"
	"openio-sds/rawx/utils"
)

type RepositoryConfiguration struct {
	putOpenMode                   uint32
	putMkdirMode                  os.FileMode
	hashWidth                     uint
	hashDepth                     uint
	shallowCopy                   bool
	syncFile                      bool
	syncDir                       bool
	fallocateFile                 bool
	openNonBlock                  bool
	fadviseUpload                 int
	fadviseDownload               int
	nonOptimalPlacementFolderPath string
	orphansFolderPath             string
}

type fileRepository struct {
	RepositoryConfiguration

	hierarchy hierarchy.Hierarchy
	manager   hierarchy.FDManager

	root string
}

const tokenPending = ".pending"

func (fr *fileRepository) openFlagsRO() int {
	flags := syscall.O_NOATIME | syscall.O_CLOEXEC | syscall.O_RDONLY
	if fr.openNonBlock {
		flags |= syscall.O_NONBLOCK
	}
	return flags
}

func (fr *fileRepository) openFlagsWO() int {
	flags := syscall.O_NOATIME | syscall.O_CLOEXEC | syscall.O_WRONLY
	if fr.openNonBlock {
		flags |= syscall.O_NONBLOCK
	}
	return flags
}

func (fr *fileRepository) init() error {
	var err error

	if err = os.MkdirAll(fr.nonOptimalPlacementFolderPath, fr.putMkdirMode); err != nil {
		return err
	}
	if err = os.MkdirAll(fr.orphansFolderPath, fr.putMkdirMode); err != nil {
		return err
	}

	fr.hierarchy = hierarchy.NewHierarchy(fr.root, fr.hashWidth, fr.hashDepth)

	fr.manager = hierarchy.NewFDManager(fr.hierarchy)
	err = fr.manager.Init()
	if err != nil {
		return fmt.Errorf("hierarchy init failed: %w", err)
	}

	return err
}

func (fr *fileRepository) rmAttr(name, key string) error {
	fd, err := fr.manager.Open(name, fr.openFlagsWO(), 0)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Fremovexattr(fd, key)
}

func (fr *fileRepository) getAttr(name, key string, value []byte) (int, error) {
	fd, err := fr.manager.Open(name, fr.openFlagsRO(), 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	return syscall.Fgetxattr(fd, key, value)
}

func (fr *fileRepository) listAttr(name string, value []byte) (int, error) {
	fd, err := fr.manager.Open(name, fr.openFlagsRO(), 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)
	return syscall.Flistxattr(fd, value)
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

// del removes a chunk from the repository.
// It will also remove appropriate extended attributes if shallow copies are enabled.
func (fr *fileRepository) del(name string) error {
	if fr.shallowCopy {
		xattrName := xattrKey(name)
		err := fr.rmAttr(name, xattrName)
		if err != nil {
			LogWarning(msgErrorAction(joinPath2("Removexattr", name), err))
		}
	}
	return fr.manager.Unlink(name)
}

func (fr *fileRepository) get(name string) (fileReader, error) {
	fd, err := fr.manager.Open(name, fr.openFlagsRO(), 0)
	if err != nil {
		return nil, err
	}

	f := &realFileReader{f: os.NewFile(uintptr(fd), name), repo: fr}

	switch fr.fadviseDownload {
	case defs.ConfigFadviseNone:
	case defs.ConfigFadviseYes:
		syscall.Fadvise(fd, 0, f.size(), syscall.FADV_SEQUENTIAL)
	case defs.ConfigFadviseNoCache:
		syscall.Fadvise(fd, 0, f.size(), syscall.FADV_DONTNEED)
	case defs.ConfigFadviseCache:
		syscall.Fadvise(fd, 0, f.size(), syscall.FADV_SEQUENTIAL)
		syscall.Fadvise(fd, 0, f.size(), syscall.FADV_WILLNEED)
	}

	return f, nil
}

// Returns true if file exists, false otherwise
func (fr *fileRepository) check(name string) bool {
	err := fr.manager.Access(name, syscall.F_OK)
	return err == nil
}

func (fr *fileRepository) put(name string) (fileWriter, error) {
	nameTemp := pendingPath(name)
	fd, err := fr.manager.Open(nameTemp, syscall.O_CREAT|syscall.O_EXCL|fr.openFlagsWO(), fr.putOpenMode)

	if err != nil {
		if os.IsNotExist(err) {
			// Lazy dir creation
			abs := fr.hierarchy.PathAbs(nameTemp)
			err = os.MkdirAll(filepath.Dir(abs), fr.putMkdirMode)
			if err == nil {
				return fr.put(name)
			}
		}
		return nil, err
	}

	// Check that the final chunk doesn't exist yet
	err = fr.manager.Access(name, syscall.F_OK)
	if err == nil {
		_ = fr.manager.Unlink(nameTemp)
		_ = syscall.Close(fd)
		return nil, os.ErrExist
	}

	return &realFileWriter{
		f:         os.NewFile(uintptr(fd), nameTemp),
		nameFinal: name, nameTemp: nameTemp, repo: fr,
		allocated: 0, written: 0}, nil
}

func (fr *fileRepository) post(name string) fileUpdater {
	return &realFileUpdater{repo: fr, absPath: fr.hierarchy.PathAbs(name)}
}

func (fr *fileRepository) createSymlinkNonOptimal(name string) error {
	LogInfo("chunk %s doesn't have an optimal placement", name)

	// Relative path of the chunk (from the rawx root) -> chunkId[:3]/
	relPath := fr.hierarchy.PathRel(name)

	// Construct relative symlink path according to:
	// <hashDepth + 1> (+1 for nonOptimalPlacementFolder)
	sb := strings.Builder{}
	for i := uint(0); i < fr.hashDepth+1; i++ {
		sb.WriteString("../")
	}
	sb.WriteString(relPath)
	// ../../chunkId[:3]/chunkId
	relOldPath := sb.String()

	// symlink name := chunk_id.nb_attempt_by_placement_improver.time_stamp_of_next_pass
	relPathWithTimeStamp := strings.Join([]string{relPath, utils.Itoa(0), utils.Itoa64(time.Now().Unix())}, ".")

	// Absolute destination of the chunk
	absNewPath := strings.Join([]string{fr.nonOptimalPlacementFolderPath, relPathWithTimeStamp}, "/")
	// Absolute path to symlink folder
	folderPath := filepath.Dir(absNewPath)
	files, err := ioutil.ReadDir(folderPath)

	if err != nil {
		// If Symlink failed because folder does not exist,
		// create it and execute the function again.
		if os.IsNotExist(err) {
			LogInfo("Create symlink dir %s", folderPath)
			// Lazy dir creation
			err = os.MkdirAll(folderPath, fr.putMkdirMode)
			if err == nil {
				return fr.createSymlinkNonOptimal(name)
			}
		}
		return err
	}
	for _, file := range files {
		// if filename contains chunkId
		if strings.Contains(file.Name(), name) {
			// Symlink already exist
			return os.ErrExist
		}
	}
	// Create the symlink
	err = syscall.Symlink(relOldPath, absNewPath)
	return err
}

func (fr *fileRepository) link(src, dst string) (linkOperation, error) {
	if !fr.shallowCopy {
		return nil, errNotImplemented
	}
	dstTemp := pendingPath(dst)
	if err := fr.manager.Link(src, dstTemp); err != nil {
		return nil, err
	}
	defer fr.manager.Unlink(dstTemp)

	if err := fr.manager.Link(dstTemp, dst); err != nil {
		return nil, err
	}

	return &realLinkOp{filename: dst, repo: fr}, nil
}

// Synchronize the parent directory, based on its path
func (fr *fileRepository) syncRelParent(filename string) error {
	if !fr.syncDir {
		return nil
	}
	fd, err := fr.manager.Parent(filename, syscall.O_DIRECTORY|fr.openFlagsRO(), 0)
	if err == nil {
		err = syscall.Fdatasync(fd)
		_ = syscall.Close(fd)
	}
	return err
}

// Synchronize just the file, based on its path
func (fr *fileRepository) syncRelFile(filename string) error {
	if !fr.syncFile {
		return nil
	}
	fd, err := fr.manager.Open(filename, fr.openFlagsRO(), 0)
	if err == nil {
		err = syscall.Fdatasync(fd)
		_ = syscall.Close(fd)
	}
	return err
}

type realLinkOp struct {
	repo     *fileRepository
	filename string
}

func (l *realLinkOp) setAttr(key string, value []byte) error {
	path := l.repo.hierarchy.PathAbs(l.filename)
	return syscall.Setxattr(path, key, value, 0)
}

func (l *realLinkOp) commit() error {
	err := l.repo.syncRelFile(l.filename)
	if err == nil {
		err = l.repo.syncRelParent(l.filename)
	}
	return err
}

func (l *realLinkOp) rollback() error {
	err := l.repo.manager.Unlink(l.filename)
	if err == nil {
		err = l.repo.syncRelParent(l.filename)
	}
	return err
}

type realFileUpdater struct {
	repo    *fileRepository
	absPath string
}

func (fu *realFileUpdater) setAttr(key string, value []byte) error {
	return syscall.Setxattr(fu.absPath, key, value, 0)
}

type realFileWriter struct {
	repo      *fileRepository
	f         *os.File
	nameFinal string
	nameTemp  string
	allocated int64
	written   int64
}

func (w *realFileWriter) fd() int {
	return int(w.f.Fd())
}

func (w *realFileWriter) setAttr(key string, value []byte) error {
	return syscall.Fsetxattr(w.fd(), key, value, 0)
}

func (w *realFileWriter) Write(buffer []byte) (int, error) {
	buflen := int64(len(buffer))

	if w.written+buflen > w.allocated {
		w.Extend(defs.UploadExtensionSize)
	}

	w.written += buflen
	return w.f.Write(buffer)
}

func (w *realFileWriter) close() {
	_ = w.f.Close()
}

func (w *realFileWriter) abort() error {
	defer w.close()

	err := w.repo.manager.Unlink(w.nameTemp)
	if err == nil {
		err = w.repo.syncRelParent(w.nameTemp)
	}
	return err
}

func (w *realFileWriter) commit() error {
	var err error
	var syncAll bool

	if w.allocated > w.written {
		err = w.f.Truncate(w.written)
		if err == nil {
			syncAll = true
		}
	}

	if err == nil {
		switch w.repo.fadviseUpload {
		case defs.ConfigFadviseNone:
		case defs.ConfigFadviseYes:
			syscall.Fadvise(w.fd(), 0, w.written, syscall.FADV_SEQUENTIAL)
		case defs.ConfigFadviseNoCache:
			syscall.Fadvise(w.fd(), 0, w.written, syscall.FADV_DONTNEED)
		case defs.ConfigFadviseCache:
			syscall.Fadvise(w.fd(), 0, w.written, syscall.FADV_SEQUENTIAL)
			syscall.Fadvise(w.fd(), 0, w.written, syscall.FADV_WILLNEED)
		}
	}

	if err == nil {
		err = w.syncFile(syncAll)
		if err == nil {
			err := w.repo.manager.Rename(w.nameTemp, w.nameFinal)
			if err == nil {
				_ = w.repo.syncRelParent(w.nameFinal)
			}
		}
	}

	if err != nil {
		w.abort()
	} else {
		w.close()
	}
	return err
}

func (w *realFileWriter) syncFile(all bool) error {
	if !w.repo.syncFile {
		return nil
	}
	if all {
		return syscall.Fsync(w.fd())
	} else {
		return syscall.Fdatasync(w.fd())
	}
}

func (w *realFileWriter) Extend(size int64) {
	if w.repo.fallocateFile {
		err := syscall.Fallocate(w.fd(), syscall.FALLOC_FL_KEEP_SIZE, w.written, size)
		if err == nil {
			w.allocated = w.written + size
		}
	}
}

type realFileReader struct {
	repo *fileRepository
	f    *os.File
}

func (r *realFileReader) fd() int {
	return int(r.f.Fd())
}

func (r *realFileReader) mtime() time.Time {
	fi, err := r.f.Stat()
	if err != nil {
		return time.Unix(0, 0)
	} else {
		return fi.ModTime()
	}
}

func (r *realFileReader) size() int64 {
	fi, err := r.f.Stat()
	if err != nil {
		return -1
	} else {
		return fi.Size()
	}
}

func (r *realFileReader) seek(offset int64) error {
	_, err := r.f.Seek(offset, os.SEEK_SET)
	return err
}

func (r *realFileReader) Close() error {
	err := r.f.Close()
	r.f = nil
	return err
}

func (r *realFileReader) Read(buffer []byte) (int, error) {
	return r.f.Read(buffer)
}

func (r *realFileReader) File() *os.File {
	return r.f
}

func (r *realFileReader) getAttr(key string, value []byte) (int, error) {
	return syscall.Fgetxattr(r.fd(), key, value)
}

func (r *realFileReader) listAttr(value []byte) (int, error) {
	return syscall.Flistxattr(r.fd(), value)
}

func setOrHasXattr(path, key, value string) error {
	buf := xattrBufferPool.Acquire()
	defer xattrBufferPool.Release(buf)

	if err := syscall.Setxattr(path, key, []byte(value), 1); err == nil {
		return nil
	} else if !os.IsExist(err) {
		return err
	}
	sz, err := syscall.Getxattr(path, key, buf)
	if err != nil {
		return err
	}
	if bytes.Equal([]byte(value), buf[:sz]) {
		return nil
	}
	return fmt.Errorf("XATTR '%s' of '%s' mismatches with '%s'",
		key, path, value)
}

func xattrKey(name string) string {
	sb := strings.Builder{}
	sb.WriteString(defs.AttrNameFullPrefix)
	sb.WriteString(name)
	return sb.String()
}

func pendingPath(filename string) string {
	sb := strings.Builder{}
	sb.WriteString(filename)
	sb.WriteString(tokenPending)
	return sb.String()
}

func joinPath2(base, file string) string {
	sb := strings.Builder{}
	sb.WriteString(base)
	sb.WriteRune('/')
	sb.WriteString(file)
	return sb.String()
}
