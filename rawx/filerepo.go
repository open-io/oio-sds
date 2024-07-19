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
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	syscall "golang.org/x/sys/unix"
	"openio-sds/rawx/defs"
	"openio-sds/rawx/utils"
)

type fileRepository struct {
	root                          string
	rootFd                        int
	putOpenMode                   uint32
	putMkdirMode                  os.FileMode
	hashWidth                     int
	hashDepth                     int
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

func (fr *fileRepository) init(root string) error {
	var err error
	basedir := filepath.Clean(root)
	if !filepath.IsAbs(basedir) {
		return errors.New("Filerepo path must be absolute")
	}
	fr.root = basedir
	fr.hashWidth = defs.HashWidthDefault
	fr.hashDepth = defs.HashDepthDefault
	fr.putOpenMode = defs.PutOpenModeDefault
	fr.putMkdirMode = defs.PutMkdirModeDefault
	fr.shallowCopy = defs.ConfigDefaultShallowCopy
	fr.syncFile = defs.ConfigDefaultSyncFile
	fr.syncDir = defs.ConfigDefaultSyncDir
	fr.fallocateFile = defs.ConfigDefaultFallocate
	fr.fadviseUpload = defs.ConfigDefaultFadviseUpload
	fr.fadviseDownload = defs.ConfigDefaultFadviseDownload
	fr.nonOptimalPlacementFolderPath = strings.Join([]string{fr.root, defs.FolderNonOptimalPlacement}, "/")
	if err = os.MkdirAll(fr.nonOptimalPlacementFolderPath, fr.putMkdirMode); err != nil {
		return err
	}
	fr.orphansFolderPath = strings.Join([]string{fr.root, defs.FolderOrphans}, "/")
	if err = os.MkdirAll(fr.orphansFolderPath, fr.putMkdirMode); err != nil {
		return err
	}
	fr.rootFd, err = syscall.Open(fr.root, syscall.O_DIRECTORY|syscall.O_PATH|fr.openFlagsRO(), 0)
	return err
}

func (fr *fileRepository) getAttr(name, key string, value []byte) (int, error) {
	return syscall.Getxattr(fr.nameToAbsPath(name), key, value)
}

func (fr *fileRepository) listAttr(name string, value []byte) (int, error) {
	return syscall.Listxattr(fr.nameToAbsPath(name), value)
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
	relPath := fr.nameToRelPath(name)
	if fr.shallowCopy {
		absPath := fr.relToAbsPath(relPath)
		xattrName := xattrKey(name)
		err := syscall.Removexattr(absPath, xattrName)
		if err != nil {
			LogWarning(msgErrorAction(joinPath2("Removexattr", name), err))
		}
	}
	return syscall.Unlinkat(fr.rootFd, relPath, 0)
}

func (fr *fileRepository) getRelPath(path string) (fileReader, error) {
	fd, err := syscall.Openat(fr.rootFd, path, fr.openFlagsRO(), 0)
	if err != nil {
		return nil, err
	}

	f := &realFileReader{f: os.NewFile(uintptr(fd), path), repo: fr}

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

func (fr *fileRepository) get(name string) (fileReader, error) {
	return fr.getRelPath(fr.nameToRelPath(name))
}

// Returns true if file exists, false otherwise
func (fr *fileRepository) check(name string) bool {
	err := syscall.Faccessat(fr.rootFd, fr.nameToRelPath(name), syscall.F_OK, 0)
	return err == nil
}

func (fr *fileRepository) putRelPath(path string) (fileWriter, error) {
	pathTemp := pendingPath(path)
	fd, err := syscall.Openat(fr.rootFd, pathTemp, syscall.O_CREAT|syscall.O_EXCL|fr.openFlagsWO(), fr.putOpenMode)
	if err != nil {
		if os.IsNotExist(err) {
			// Lazy dir creation
			abs := fr.relToAbsPath(path)
			err = os.MkdirAll(filepath.Dir(abs), fr.putMkdirMode)
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
		f:         os.NewFile(uintptr(fd), pathTemp),
		pathFinal: path, pathTemp: pathTemp, repo: fr,
		allocated: 0, written: 0}, nil
}

func (fr *fileRepository) put(name string) (fileWriter, error) {
	return fr.putRelPath(fr.nameToRelPath(name))
}

func (fr *fileRepository) post(name string) fileUpdater {
	return &realFileUpdater{repo: fr, path: fr.nameToRelPath(name)}
}

func (fr *fileRepository) createSymlinkNonOptimal(name string) error {
	LogInfo("chunk %s doesn't have an optimal placement", name)

	// Relative path of the chunk (from the rawx root) -> chunkId[:3]/
	relPath := fr.nameToRelPath(name)
	// Construct relative symlink path according to:
	// <hashDepth + 1> (+1 for nonOptimalPlacementFolder)
	sb := strings.Builder{}
	for i := 0; i < fr.hashDepth+1; i++ {
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

// Fast path: initial optimistic attempt when everything works fine
// (i.e. when the source exists and the target directory exists).
func (fr *fileRepository) linkRelPath_FastPath(fromPath, toPath string) (linkOperation, error) {
	pathTemp := pendingPath(toPath)

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
			if e0 := os.MkdirAll(filepath.Dir(filepath.Join(fr.root, toPath)),
				fr.putMkdirMode); e0 != nil {
				return nil, err
			}
		default:
			// The initial link() failed
			return nil, err
		}
	}
}

func (fr *fileRepository) link(src, dst string) (linkOperation, error) {
	if !fr.shallowCopy {
		return nil, errNotImplemented
	}
	relSrc := fr.nameToRelPath(src)
	relDst := fr.nameToRelPath(dst)
	return fr.linkRelPath(relSrc, relDst)
}

// Synchronize the parent directory, based on its path
func (fr *fileRepository) syncRelParent(path string) error {
	if !fr.syncDir {
		return nil
	}
	parent := filepath.Dir(path)
	fd, err := syscall.Openat(fr.rootFd, parent, syscall.O_DIRECTORY|fr.openFlagsRO(), 0)
	if err == nil {
		err = syscall.Fdatasync(fd)
		syscall.Close(fd)
	}
	return err

}

// Synchronize just the file, based on its path
func (fr *fileRepository) syncRelFile(relPath string) error {
	if !fr.syncFile {
		return nil
	}
	fd, err := syscall.Openat(fr.rootFd, relPath, fr.openFlagsRO(), 0)
	if err == nil {
		err = syscall.Fdatasync(fd)
		syscall.Close(fd)
	}
	return err
}

type realLinkOp struct {
	relPath string
	repo    *fileRepository
}

func (lo *realLinkOp) setAttr(key string, value []byte) error {
	path := joinPath2(lo.repo.root, lo.relPath)
	return syscall.Setxattr(path, key, value, 0)
}

func (lo *realLinkOp) commit() error {
	err := lo.repo.syncRelFile(lo.relPath)
	if err == nil {
		err = lo.repo.syncRelParent(lo.relPath)
	}
	return err
}

func (lo *realLinkOp) rollback() error {
	err := syscall.Unlinkat(lo.repo.rootFd, lo.relPath, 0)
	if err == nil {
		err = lo.repo.syncRelParent(lo.relPath)
	}
	return err
}

type realFileUpdater struct {
	repo *fileRepository
	path string
}

func (fu *realFileUpdater) setAttr(key string, value []byte) error {
	path := joinPath2(fu.repo.root, fu.path)
	return syscall.Setxattr(path, key, value, 0)
}

type realFileWriter struct {
	f         *os.File
	repo      *fileRepository
	pathFinal string
	pathTemp  string
	allocated int64
	written   int64
}

func (fw *realFileWriter) fd() int {
	return int(fw.f.Fd())
}

func (fw *realFileWriter) setAttr(key string, value []byte) error {
	return syscall.Fsetxattr(fw.fd(), key, value, 0)
}

func (fw *realFileWriter) updateAttr(key string, value []byte) error {
	return syscall.Setxattr(fw.pathFinal, key, value, 0)
}

func (fw *realFileWriter) Write(buffer []byte) (int, error) {
	buflen := int64(len(buffer))

	if fw.written+buflen > fw.allocated {
		fw.Extend(defs.UploadExtensionSize)
	}

	fw.written += buflen
	return fw.f.Write(buffer)
}

func (fw *realFileWriter) close() {
	_ = fw.f.Close()
}

func (fw *realFileWriter) abort() error {
	defer fw.close()

	err := syscall.Unlinkat(fw.repo.rootFd, fw.pathTemp, 0)
	if err == nil {
		err = fw.repo.syncRelParent(fw.pathTemp)
	}
	return err
}

func (fw *realFileWriter) commit() error {
	var err error
	var syncAll bool

	if fw.allocated > fw.written {
		err = fw.f.Truncate(fw.written)
		if err == nil {
			syncAll = true
		}
	}

	if err == nil {
		switch fw.repo.fadviseUpload {
		case defs.ConfigFadviseNone:
		case defs.ConfigFadviseYes:
			syscall.Fadvise(fw.fd(), 0, fw.written, syscall.FADV_SEQUENTIAL)
		case defs.ConfigFadviseNoCache:
			syscall.Fadvise(fw.fd(), 0, fw.written, syscall.FADV_DONTNEED)
		case defs.ConfigFadviseCache:
			syscall.Fadvise(fw.fd(), 0, fw.written, syscall.FADV_SEQUENTIAL)
			syscall.Fadvise(fw.fd(), 0, fw.written, syscall.FADV_WILLNEED)
		}
	}

	if err == nil {
		err = fw.syncFile(syncAll)
		if err == nil {
			err := syscall.Renameat(fw.repo.rootFd, fw.pathTemp, fw.repo.rootFd, fw.pathFinal)
			if err == nil {
				_ = fw.repo.syncRelParent(fw.pathFinal)
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

func (fw *realFileWriter) syncFile(all bool) error {
	if !fw.repo.syncFile {
		return nil
	}
	if all {
		return syscall.Fsync(fw.fd())
	} else {
		return syscall.Fdatasync(fw.fd())
	}
}

func (fw *realFileWriter) Extend(size int64) {
	if fw.repo.fallocateFile {
		err := syscall.Fallocate(fw.fd(), syscall.FALLOC_FL_KEEP_SIZE, fw.written, size)
		if err == nil {
			fw.allocated = fw.written + size
		}
	}
}

type realFileReader struct {
	f    *os.File
	repo *fileRepository
}

func (fr *realFileReader) fd() int {
	return int(fr.f.Fd())
}

func (fr *realFileReader) mtime() time.Time {
	fi, err := fr.f.Stat()
	if err != nil {
		return time.Unix(0, 0)
	} else {
		return fi.ModTime()
	}
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
	return syscall.Fgetxattr(fr.fd(), key, value)
}

func (fr *realFileReader) listAttr(value []byte) (int, error) {
	return syscall.Flistxattr(fr.fd(), value)
}

func (fr *fileRepository) nameToRelPath(name string) string {
	sb := strings.Builder{}
	for i := 0; i < fr.hashDepth; i++ {
		start := i * fr.hashWidth
		sb.WriteString(name[start : start+fr.hashWidth])
		sb.WriteRune('/')
	}
	sb.WriteString(name)
	return sb.String()
}

func (fr *fileRepository) nameToAbsPath(name string) string {
	return fr.relToAbsPath(fr.nameToRelPath(name))
}

func (fr *fileRepository) relToAbsPath(path string) string {
	return joinPath2(fr.root, path)
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

func pendingPath(path string) string {
	sb := strings.Builder{}
	sb.WriteString(path)
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
