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
	"syscall"
)

const (
	hashWidth    = 3
	hashDepth    = 1
	putOpenFlags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	putOpenMode  = 0644
	putMkdirMode = 0755
)

type fileRepository struct {
	root          string
	rootFd        int
	putOpenMode   os.FileMode
	putOpenFlags  int
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
	fr.putOpenFlags = putOpenFlags
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

func (fileRepo *fileRepository) lock(ns, id string) error {
	var err error
	err = setOrHasXattr(fileRepo.root, "user.server.id", id)
	if err != nil {
		return err
	}
	err = setOrHasXattr(fileRepo.root, "user.server.ns", ns)
	if err != nil {
		return err
	}
	err = setOrHasXattr(fileRepo.root, "user.server.type", "rawx")
	if err != nil {
		return err
	}
	return nil
}

func (fileRepo *fileRepository) has(name string) (bool, error) {
	path := fileRepo.nameToPath(name)
	if _, err := os.Stat(path); err != nil {
		return false, err
	} else {
		return true, nil
	}
}

func (fileRepo *fileRepository) del(name string) error {
	path := fileRepo.nameToPath(name)
	err := syscall.Removexattr(path, AttrNameFullPrefix+name)
	if err != nil {
		LogWarning("Error to remove content fullpath: %s", err)
		err = nil
	}
	return os.Remove(path)
}

func (fileRepo *fileRepository) realGet(path string) (fileReader, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	fileReader := new(realFileReader)
	fileReader.impl = f
	fileReader.path = path
	return fileReader, nil
}

func (fileRepo *fileRepository) get(name string) (fileReader, error) {
	path := fileRepo.nameToPath(name)
	return fileRepo.realGet(path)
}

func (fileRepo *fileRepository) realPut(path string) (fileWriter, error) {
	// Check if the path doesn't exist yet
	if _, err := os.Stat(path); err == nil {
		return nil, os.ErrExist
	}

	pathTemp := path + ".pending"
	f, err := os.OpenFile(pathTemp, fileRepo.putOpenFlags, fileRepo.putOpenMode)
	if err != nil {
		if os.IsNotExist(err) {
			// Lazy dir creation
			err = os.MkdirAll(filepath.Dir(path), fileRepo.putMkdirMode)
			if err == nil {
				return fileRepo.realPut(path)
			}
		}
		return nil, err
	}

	return &realFileWriter{
		pathFinal: path, pathTemp: pathTemp, impl: f,
		syncFileBool: fileRepo.syncFile, syncDirBool: fileRepo.syncDir}, nil
}

func (fileRepo *fileRepository) put(name string) (fileWriter, error) {
	path := fileRepo.nameToPath(name)
	return fileRepo.realPut(path)
}

func (fileRepo *fileRepository) realLink(fromPath, toPath string) (fileWriter, error) {
	// Check if the source already exists
	if _, err := os.Stat(fromPath); os.IsNotExist(err) {
		return nil, os.ErrNotExist
	}
	// Check if the destination doesn't exist yet
	if _, err := os.Stat(toPath); err == nil {
		return nil, os.ErrExist
	}

	pathTemp := toPath + ".pending"
	if err := os.Link(fromPath, pathTemp); err != nil {
		if os.IsNotExist(err) {
			// Lazy dir creation
			err = os.MkdirAll(filepath.Dir(toPath), fileRepo.putMkdirMode)
			if err == nil {
				return fileRepo.realLink(fromPath, toPath)
			}
		}
		return nil, err
	}

	f, err := os.OpenFile(pathTemp, os.O_WRONLY, 0)
	if err != nil {
		os.Remove(pathTemp)
		f.Close()
		return nil, err
	}
	return &realFileWriter{
		pathFinal: toPath, pathTemp: pathTemp, impl: f,
		syncFileBool: fileRepo.syncFile, syncDirBool: fileRepo.syncDir}, nil
}

func (fileRepo *fileRepository) link(fromName, toName string) (fileWriter, error) {
	fromPath := fileRepo.nameToPath(fromName)
	toPath := fileRepo.nameToPath(toName)
	return fileRepo.realLink(fromPath, toPath)
}

// Takes only the basename, check it is hexadecimal with a length of 64,
// and computes the hashed path
func (fileRepo *fileRepository) nameToPath(name string) string {
	var result strings.Builder
	result.WriteString(fileRepo.root)
	for i := 0; i < fileRepo.hashDepth; i++ {
		start := i * fileRepo.hashDepth
		result.WriteRune('/')
		result.WriteString(name[start : start+fileRepo.hashWidth])
	}
	result.WriteRune('/')
	result.WriteString(name)
	return result.String()
}

type realFileWriter struct {
	pathFinal    string
	pathTemp     string
	impl         *os.File
	syncFileBool bool
	syncDirBool  bool
}

func (fileWriter *realFileWriter) seek(offset int64) error {
	_, err := fileWriter.impl.Seek(offset, os.SEEK_SET)
	return err
}

func (fileWriter *realFileWriter) setAttr(key string, value []byte) error {
	return syscall.Setxattr(fileWriter.pathTemp, key, value, 0)
}

func (fileWriter *realFileWriter) sync() error {
	return fileWriter.impl.Sync()
}

func (fileWriter *realFileWriter) Write(buffer []byte) (int, error) {
	return fileWriter.impl.Write(buffer)
}

func (fileWriter *realFileWriter) abort() error {
	os.Remove(fileWriter.pathTemp)
	return fileWriter.impl.Close()
}

func (fileWriter *realFileWriter) syncFile() {
	if fileWriter.syncFileBool {
		//w.impl.Sync()
		syscall.Fdatasync(int(fileWriter.impl.Fd()))
	}
}

func (fileWriter *realFileWriter) syncDir() {
	if fileWriter.syncDirBool {
		dir := filepath.Dir(fileWriter.pathFinal)
		if f, err := os.OpenFile(dir, os.O_RDONLY, 0); err == nil {
			f.Sync()
			f.Close()
		} else {
			LogWarning("Directory sync error: %s", err)
		}
	}
}

func (fileWriter *realFileWriter) commit() error {
	fileWriter.syncFile()
	err := fileWriter.impl.Close()
	if err == nil {
		err = os.Rename(fileWriter.pathTemp, fileWriter.pathFinal)
		if err == nil {
			fileWriter.syncDir()
		} else {
			LogError("Rename error: %s", err)
		}
	} else {
		LogError("Close error: %s", err)
	}
	if err != nil {
		os.Remove(fileWriter.pathTemp)
	}
	return err
}

type realFileReader struct {
	path string
	impl *os.File
}

func (fileReader *realFileReader) size() int64 {
	fi, _ := fileReader.impl.Stat()
	return fi.Size()
}

func (fileReader *realFileReader) seek(offset int64) error {
	_, err := fileReader.impl.Seek(offset, os.SEEK_SET)
	return err
}

func (fileReader *realFileReader) Close() error {
	return fileReader.impl.Close()
}

func (fileReader *realFileReader) Read(buffer []byte) (int, error) {
	return fileReader.impl.Read(buffer)
}

func (fileReader *realFileReader) getAttr(key string) ([]byte, error) {
	tmp := make([]byte, 2048)
	sz, err := syscall.Getxattr(fileReader.path, key, tmp)
	if err != nil {
		return nil, err
	}
	return tmp[:sz], nil
}

func (fileReader *realFileReader) check() (string, error) {
	h := md5.New()
	if _, err := io.Copy(h, fileReader.impl); err != nil {
		return "", err
	}

	return strings.ToUpper(hex.EncodeToString(h.Sum(nil))), nil
}
