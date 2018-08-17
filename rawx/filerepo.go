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

import (
	"bytes"
	"container/list"
	"errors"
	"io/ioutil"
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

type FileRepository struct {
	root          string
	putOpenMode   os.FileMode
	putOpenFlags  int
	putMkdirMode  os.FileMode
	HashWidth     int
	HashDepth     int
	SyncFile      bool
	SyncDir       bool
	FallocateFile bool
}

func MakeFileRepository(root string) *FileRepository {
	fileRepo := new(FileRepository)
	fileRepo.root = root
	fileRepo.HashWidth = hashWidth
	fileRepo.HashDepth = hashDepth
	fileRepo.putOpenFlags = putOpenFlags
	fileRepo.putOpenMode = putOpenMode
	fileRepo.putMkdirMode = putMkdirMode
	fileRepo.SyncFile = false
	fileRepo.SyncDir = true

	return fileRepo
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

func (fileRepo *FileRepository) Lock(ns, id string) error {
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

func (fileRepo *FileRepository) Has(name string) (bool, error) {
	if p, err := fileRepo.nameToPath(name); err != nil {
		return false, err
	} else if _, err := os.Stat(p); err != nil {
		return false, err
	} else {
		return true, nil
	}
}

func (fileRepo *FileRepository) Del(name string) error {
	path, err := fileRepo.nameToPath(name)
	if err != nil {
		return err
	}
	err = syscall.Removexattr(path, AttrNameFullPrefix+name)
	if err != nil {
		LogWarning("Error to remove content fullpath: %s", err)
		err = nil
	}
	return os.Remove(path)
}

func (fileRepo *FileRepository) realGet(path string) (FileReader, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	fileReader := new(RealFileReader)
	fileReader.impl = f
	fileReader.path = path
	return fileReader, nil
}

func (fileRepo *FileRepository) Get(name string) (FileReader, error) {
	path, err := fileRepo.nameToPath(name)
	if err != nil {
		return nil, err
	}
	return fileRepo.realGet(path)
}

func (fileRepo *FileRepository) realPut(path string) (FileWriter, error) {
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

	return &RealFileWriter{
		pathFinal: path, pathTemp: pathTemp, impl: f,
		syncFileBool: fileRepo.SyncFile, syncDirBool: fileRepo.SyncDir}, nil
}

func (fileRepo *FileRepository) Put(name string) (FileWriter, error) {
	path, err := fileRepo.nameToPath(name)
	if err != nil {
		return nil, err
	}
	return fileRepo.realPut(path)
}

func (fileRepo *FileRepository) realLink(fromPath, toPath string) (FileWriter, error) {
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
	return &RealFileWriter{
		pathFinal: toPath, pathTemp: pathTemp, impl: f,
		syncFileBool: fileRepo.SyncFile, syncDirBool: fileRepo.SyncDir}, nil
}

func (fileRepo *FileRepository) Link(fromName, toName string) (FileWriter, error) {
	fromPath, err := fileRepo.nameToPath(fromName)
	if err != nil {
		return nil, err
	}
	toPath, err := fileRepo.nameToPath(toName)
	if err != nil {
		return nil, err
	}
	return fileRepo.realLink(fromPath, toPath)
}

func (fileRepo *FileRepository) nameToPathTokens(name string) ([]string, error) {

	// Sanity checks and cleanups
	if len(name) <= 0 {
		return make([]string, 0, 0), os.ErrInvalid
	}
	name = strings.Replace(filepath.Clean(name), "/", "@", -1)

	// Hash computations
	tokens := make([]string, 0, 5)
	tokens = append(tokens, fileRepo.root)
	for i := 0; i < fileRepo.HashDepth; i++ {
		start := i * fileRepo.HashDepth
		tokens = append(tokens, name[start:start+fileRepo.HashWidth])
	}

	return tokens, nil
}

// Takes only the basename, check it is hexadecimal with a length of 64,
// and computes the hashed path
func (fileRepo *FileRepository) nameToPath(name string) (string, error) {
	tokens, err := fileRepo.nameToPathTokens(name)
	if err != nil {
		return "", err
	}
	tokens = append(tokens, name)
	return filepath.Join(tokens...), nil
}

func (fileRepo *FileRepository) List(marker, prefix string, max int) (ListSlice, error) {
	out := ListSlice{make([]string, 0, 0), false}

	// If both a prefix and a marker are set, if the marker is already
	// greater than the prefix, no need to continue
	if len(prefix) > 0 && len(marker) > 0 {
		if marker > prefix {
			out.Truncated = true
			return out, nil
		}
	}

	// Compute a path that is long enough to compute a full hashed directory,
	// that is lexicographically greater than the marker
	minLength := fileRepo.HashWidth * fileRepo.HashDepth
	start := string(marker)
	if prefix > start {
		start = string(prefix)
	}
	if len(start) < minLength {
		start = start + strings.Repeat(" ", minLength)
	}

	tokens, err := fileRepo.nameToPathTokens(start)
	if err != nil {
		return out, err
	}

	// Iterate

	stack := list.New()
	if l0, err := ioutil.ReadDir(fileRepo.root); err == nil {
		for _, item := range l0 {
			if item.Name() < tokens[0] {
				continue
			}
			stack.PushFront(item)
		}
	}

	// Deduce the starting directory for the fi
	return out, ErrNotImplemented
}

type RealFileWriter struct {
	pathFinal    string
	pathTemp     string
	impl         *os.File
	syncFileBool bool
	syncDirBool  bool
}

func (fileWriter *RealFileWriter) Seek(offset int64) error {
	_, err := fileWriter.impl.Seek(offset, os.SEEK_SET)
	return err
}

func (fileWriter *RealFileWriter) SetAttr(key string, value []byte) error {
	return syscall.Setxattr(fileWriter.pathTemp, key, value, 0)
}

func (fileWriter *RealFileWriter) Sync() error {
	return fileWriter.impl.Sync()
}

func (fileWriter *RealFileWriter) Write(buffer []byte) (int, error) {
	return fileWriter.impl.Write(buffer)
}

func (fileWriter *RealFileWriter) Abort() error {
	os.Remove(fileWriter.pathTemp)
	return fileWriter.impl.Close()
}

func (fileWriter *RealFileWriter) syncFile() {
	if fileWriter.syncFileBool {
		//w.impl.Sync()
		syscall.Fdatasync(int(fileWriter.impl.Fd()))
	}
}

func (fileWriter *RealFileWriter) syncDir() {
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

func (fileWriter *RealFileWriter) Commit() error {
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

type RealFileReader struct {
	path string
	impl *os.File
}

func (fileReader *RealFileReader) Size() int64 {
	fi, _ := fileReader.impl.Stat()
	return fi.Size()
}

func (fileReader *RealFileReader) Seek(offset int64) error {
	_, err := fileReader.impl.Seek(offset, os.SEEK_SET)
	return err
}

func (fileReader *RealFileReader) Close() error {
	return fileReader.impl.Close()
}

func (fileReader *RealFileReader) Read(buffer []byte) (int, error) {
	return fileReader.impl.Read(buffer)
}

func (fileReader *RealFileReader) GetAttr(key string) ([]byte, error) {
	tmp := make([]byte, 256)
	sz, err := syscall.Getxattr(fileReader.path, key, tmp)
	if err != nil {
		return nil, err
	}
	return tmp[:sz], nil
}
