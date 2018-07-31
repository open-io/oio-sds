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

type NoopNotifier struct{}

func (self *NoopNotifier) NotifyPut(n string) {}
func (self *NoopNotifier) NotifyDel(n string) {}

type Notifier interface {
	NotifyPut(name string)
	NotifyDel(name string)
}

type FileRepository struct {
	notifier       Notifier
	root           string
	putOpenMode    os.FileMode
	putMkdirMode   os.FileMode
	HashWidth      int
	HashDepth      int
	putOpenFlags   int
	sync_file      bool
	sync_dir       bool
	fallocate_file bool
}

func MakeFileRepository(root string, notifier Notifier) *FileRepository {
	r := new(FileRepository)
	if notifier == nil {
		r.notifier = &NoopNotifier{}
	} else {
		r.notifier = notifier
	}
	r.root = root
	r.HashWidth = hashWidth
	r.HashDepth = hashDepth
	r.putOpenFlags = putOpenFlags
	r.putOpenMode = putOpenMode
	r.putMkdirMode = putMkdirMode
	r.sync_file = false
	r.sync_dir = true

	return r
}

func setOrHasXattr(path, n, v string) error {
	if err := syscall.Setxattr(path, n, []byte(v), 1); err == nil {
		return nil
	} else if !os.IsExist(err) {
		return err
	}
	tab := make([]byte, 256)
	sz, err := syscall.Getxattr(path, n, tab)
	if err != nil {
		return err
	}
	if bytes.Equal([]byte(v), tab[:sz]) {
		return nil
	} else {
		return errors.New("XATTR mismatch")
	}
}

func (r *FileRepository) Lock(ns, id string) error {
	var err error
	err = setOrHasXattr(r.root, "user.server.id", id)
	if err != nil {
		return err
	}
	err = setOrHasXattr(r.root, "user.server.ns", ns)
	if err != nil {
		return err
	}
	err = setOrHasXattr(r.root, "user.server.type", "rawx")
	if err != nil {
		return err
	}
	return nil
}

func (r *FileRepository) Has(name string) (bool, error) {
	if p, err := r.nameToPath(name); err != nil {
		return false, err
	} else if _, err := os.Stat(p); err != nil {
		return false, err
	} else {
		return true, nil
	}
}

func (r *FileRepository) Del(name string) error {
	if p, err := r.nameToPath(name); err != nil {
		return err
	} else {
		err = os.Remove(p)
		if err == nil {
			r.notifier.NotifyDel(name)
		}
		return err
	}
}

func realGet(p string) (FileReader, error) {
	if f, err := os.OpenFile(p, os.O_RDONLY, 0); err != nil {
		return nil, err
	} else {
		r := new(RealFileReader)
		r.impl = f
		r.path = p
		return r, nil
	}
}

func (r *FileRepository) Get(name string) (FileReader, error) {
	if p, err := r.nameToPath(name); err != nil {
		return nil, err
	} else {
		return realGet(p)
	}
}

func (r *FileRepository) realPut(path string) (FileWriter, error) {
	// Check if the path doesn't exist yet
	if _, err := os.Stat(path); err == nil {
		return nil, os.ErrExist
	}

	pathTemp := path + ".pending"
	f, err := os.OpenFile(pathTemp, r.putOpenFlags, r.putOpenMode)
	if err != nil {
		if os.IsNotExist(err) {
			// Lazy dir creation
			err = os.MkdirAll(filepath.Dir(path), r.putMkdirMode)
			if err == nil {
				return r.realPut(path)
			}
		}
		return nil, err
	}

	return &RealFileWriter{
		path_final: path, path_temp: pathTemp,
		impl: f, notifier: r.notifier,
		sync_file: r.sync_file, sync_dir: r.sync_dir,
	}, nil
}

func (r *FileRepository) Put(name string) (FileWriter, error) {
	path, err := r.nameToPath(name)
	if err != nil {
		return nil, err
	}
	return r.realPut(path)
}

func (r *FileRepository) realLink(fromPath, toPath string) (FileWriter, error) {
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
			err = os.MkdirAll(filepath.Dir(toPath), r.putMkdirMode)
			if err == nil {
				return r.realLink(fromPath, toPath)
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
		path_final: toPath, path_temp: pathTemp, impl: f,
		notifier: r.notifier, sync_file: r.sync_file, sync_dir: r.sync_dir}, nil
}

func (r *FileRepository) Link(fromName, toName string) (FileWriter, error) {
	fromPath, err := r.nameToPath(fromName)
	if err != nil {
		return nil, err
	}
	toPath, err := r.nameToPath(toName)
	if err != nil {
		return nil, err
	}
	return r.realLink(fromPath, toPath)
}

func (r *FileRepository) nameToPathTokens(name string) ([]string, error) {

	// Sanity checks and cleanups
	if len(name) <= 0 {
		return make([]string, 0, 0), os.ErrInvalid
	}
	name = strings.Replace(filepath.Clean(name), "/", "@", -1)

	// Hash computations
	tokens := make([]string, 0, 5)
	tokens = append(tokens, r.root)
	for i := 0; i < r.HashDepth; i++ {
		start := i * r.HashDepth
		tokens = append(tokens, name[start:start+r.HashWidth])
	}

	return tokens, nil
}

// Takes only the basename, check it is hexadecimal with a length of 64,
// and computes the hashed path
func (r *FileRepository) nameToPath(name string) (string, error) {
	if tokens, err := r.nameToPathTokens(name); err != nil {
		return "", err
	} else {
		tokens = append(tokens, name)
		return filepath.Join(tokens...), nil
	}
}

type RealFileWriter struct {
	path_final string
	path_temp  string
	impl       *os.File
	notifier   Notifier
	sync_file  bool
	sync_dir   bool
}

func (w *RealFileWriter) Seek(o int64) error {
	_, err := w.impl.Seek(o, os.SEEK_SET)
	return err
}

func (w *RealFileWriter) SetAttr(n string, v []byte) error {
	return syscall.Setxattr(w.path_temp, n, v, 0)
}

func (w *RealFileWriter) Sync() error {
	return w.impl.Sync()
}

func (w *RealFileWriter) Write(buf []byte) (int, error) {
	return w.impl.Write(buf)
}

func (w *RealFileWriter) Abort() error {
	os.Remove(w.path_temp)
	return w.impl.Close()
}

func (w *RealFileWriter) syncFile() {
	if w.sync_file {
		//w.impl.Sync()
		syscall.Fdatasync(int(w.impl.Fd()))
	}
}

func (w *RealFileWriter) syncDir() {
	if w.sync_dir {
		dir := filepath.Dir(w.path_final)
		if f, err := os.OpenFile(dir, os.O_RDONLY, 0); err == nil {
			f.Sync()
			f.Close()
		} else {
			logger_error.Print("Directory sync error: ", err)
		}
	}
}

func (w *RealFileWriter) Commit() error {
	w.syncFile()
	err := w.impl.Close()
	if err == nil {
		err = os.Rename(w.path_temp, w.path_final)
		if err == nil {
			w.syncDir()
			// TODO(adu) w.notifier.NotifyPut(w.name)
		} else {
			logger_error.Print("Rename error: ", err)
		}
	} else {
		logger_error.Print("Close error: ", err)
	}
	if err != nil {
		os.Remove(w.path_temp)
	}
	return err
}

type RealFileReader struct {
	path string
	impl *os.File
}

func (r *RealFileReader) Size() int64 {
	fi, _ := r.impl.Stat()
	return fi.Size()
}

func (r *RealFileReader) Seek(o int64) error {
	_, err := r.impl.Seek(o, os.SEEK_SET)
	return err
}

func (r *RealFileReader) Close() error {
	return r.impl.Close()
}

func (r *RealFileReader) Read(buf []byte) (int, error) {
	return r.impl.Read(buf)
}

func (r *RealFileReader) GetAttr(n string) ([]byte, error) {
	tmp := make([]byte, 256)
	sz, err := syscall.Getxattr(r.path, n, tmp)
	if err != nil {
		return nil, err
	} else {
		return tmp[:sz], nil
	}
}

func (self *FileRepository) List(marker, prefix string, max int) (ListSlice, error) {
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
	min_length := self.HashWidth * self.HashDepth
	start := string(marker)
	if prefix > start {
		start = string(prefix)
	}
	if len(start) < min_length {
		start = start + strings.Repeat(" ", min_length)
	}

	tokens, err := self.nameToPathTokens(start)
	if err != nil {
		return out, err
	}

	// Iterate

	stack := list.New()
	if l0, err := ioutil.ReadDir(self.root); err == nil {
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
