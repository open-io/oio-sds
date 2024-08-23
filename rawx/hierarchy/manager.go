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

package hierarchy

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"

	syscall "golang.org/x/sys/unix"
)

const (
	dirOpenFlags = syscall.O_PATH | syscall.O_DIRECTORY | syscall.O_NOATIME | syscall.O_CLOEXEC | syscall.O_NONBLOCK | syscall.O_RDWR
)

const (
	dirCreateMode = 0755
)

type FDManager interface {
	io.Closer
	Init() error

	Access(path string, mode uint32) error
	Open(path string, flags int, mode uint32) (int, error)
	Parent(path string, flags int, mode uint32) (int, error)
	Rename(oldPath, newPath string) error
	Unlink(path string) error
	Link(oldPath, newPath string) error
}

func NewFDManager(h Hierarchy) FDManager {
	maxFD := h.CountPrefixes()
	out := &cache{
		latch:     sync.RWMutex{},
		hierarchy: h,

		rootFd:  -1,
		fdCache: make([]int, maxFD),
	}
	for i := uint64(0); i < maxFD; i++ {
		out.fdCache[i] = -1
	}
	return out
}

type cache struct {
	latch     sync.RWMutex
	hierarchy Hierarchy

	rootFd  int
	fdCache []int
}

const fdUsageReserve uint64 = 256

func (c *cache) Init() error {
	var err error
	c.rootFd, err = syscall.Open(c.hierarchy.Basedir(), dirOpenFlags, 0)
	if err != nil {
		return err
	}

	err = c.createHierarchy()
	if err != nil {
		_ = c.Close()
	} else {
		lim := syscall.Rlimit{}
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
			return fmt.Errorf("getrlimit(NOFILE): %w", err)
		}

		limitRequiredForCache := fdUsageReserve + c.hierarchy.CountPrefixes()
		log.Printf("getrlimit(NOFILE) cur=%d max=%d required=%d", lim.Cur, lim.Max, limitRequiredForCache)

		if lim.Cur < limitRequiredForCache && lim.Max >= limitRequiredForCache {
			lim.Cur = lim.Max
			if err = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
				return fmt.Errorf("setrlimit(NOFILE): %w", err)
			}
		}

		if lim.Cur < limitRequiredForCache {
			//log.Printf("cache disable because of too few FD (limit %d)", limitRequiredForCache)
		} else {
			err = c.cacheHierarchy()
			if err != nil {
				_ = c.Close()
			}
		}
	}

	return err
}

func (c *cache) Close() error {
	c.latch.Lock()
	defer c.latch.Unlock()

	if c.rootFd != -1 {
		_ = syscall.Close(c.rootFd)
		c.rootFd = -1
	}

	for i, fd := range c.fdCache {
		if fd != -1 {
			_ = syscall.Close(fd)
			c.fdCache[i] = -1
		}
	}
	return nil
}

func (c *cache) Access(filename string, mode uint32) error {
	c.latch.RLock()
	defer c.latch.RUnlock()

	fd := c.parentFD(filename)
	if fd >= 0 {
		return syscall.Faccessat(fd, filename, mode, 0)
	} else {
		rel := c.hierarchy.PathRel(filename)
		return syscall.Faccessat(c.rootFd, rel, mode, 0)
	}
}

func (c *cache) Open(filename string, flags int, mode uint32) (int, error) {
	c.latch.RLock()
	defer c.latch.RUnlock()

	pfd := c.parentFD(filename)
	if pfd >= 0 {
		fd, err := syscall.Openat(pfd, filename, flags, mode)
		if err != nil {
			return -1, err
		} else {
			return fd, nil
		}
	} else {
		path := c.hierarchy.PathRel(filename)
		fd, err := syscall.Openat(c.rootFd, path, flags, mode)
		if err != nil {
			return -1, err
		} else {
			return fd, nil
		}
	}
}

func (c *cache) Parent(filename string, flags int, mode uint32) (int, error) {
	c.latch.RLock()
	defer c.latch.RUnlock()

	var err error
	fd := c.parentFD(filename)
	if fd >= 0 {
		return syscall.Dup(fd)
	} else {
		path := c.hierarchy.Prefix(filename)
		fd, err = syscall.Openat(c.rootFd, path, flags, mode)
		if err != nil {
			return -1, err
		} else {
			return fd, nil
		}
	}
}

func (c *cache) Rename(oldPath, newPath string) error {
	c.latch.RLock()
	defer c.latch.RUnlock()

	// very-fast path : we have an open handle to both dirs
	if oldFD := c.parentFD(oldPath); oldFD >= 0 {
		if newFD := c.parentFD(newPath); newFD >= 0 {
			// both parents are cached
			return syscall.Renameat2(oldFD, oldPath, newFD, newPath, syscall.RENAME_NOREPLACE)
		}
	}

	// fast path : both dirs exists
	newParentRel := c.hierarchy.PathRel(newPath)
	oldParentRel := c.hierarchy.PathRel(oldPath)
	err := syscall.Renameat2(c.rootFd, oldParentRel, c.rootFd, newParentRel, syscall.RENAME_NOREPLACE)
	if err == nil {
		return nil
	}

	switch err.(syscall.Errno) {
	case syscall.ENOENT:
		// Slow path : need to create the target directory. If the source directory doesn't exist,
		// no need to create it, because ENOENT is the correct answer
		newParentAbs := c.hierarchy.PathAbs(newPath)
		if e1 := os.MkdirAll(newParentAbs, dirCreateMode); e1 != nil {
			return nil
		}
		return syscall.Renameat2(c.rootFd, oldParentRel, c.rootFd, newParentRel, syscall.RENAME_NOREPLACE)
	default:
		return err
	}
}

func (c *cache) Unlink(filename string) error {
	c.latch.RLock()
	defer c.latch.RUnlock()

	if fd := c.parentFD(filename); fd >= 0 {
		return syscall.Unlinkat(fd, filename, 0)
	} else {
		path := c.hierarchy.PathRel(filename)
		return syscall.Unlinkat(c.rootFd, path, 0)
	}
}

func (c *cache) Link(oldPath, newPath string) error {
	c.latch.RLock()
	defer c.latch.RUnlock()

	// very-fast path : we have an open handle to both dirs
	if oldFD := c.parentFD(oldPath); oldFD >= 0 {
		if newFD := c.parentFD(newPath); newFD >= 0 {
			// both parents are cached
			return syscall.Linkat(oldFD, oldPath, newFD, newPath, 0)
		}
	}

	// fast path : both dirs exists
	newParentRel := c.hierarchy.PathRel(newPath)
	oldParentRel := c.hierarchy.PathRel(oldPath)
	err := syscall.Linkat(c.rootFd, oldParentRel, c.rootFd, newParentRel, 0)
	if err == nil {
		return nil
	}

	switch err.(syscall.Errno) {
	case syscall.ENOENT:
		// Slow path : need to create the target directory
		newParentAbs := c.hierarchy.PathAbs(newPath)
		if e1 := os.MkdirAll(newParentAbs, dirCreateMode); e1 != nil {
			return nil
		}
		return syscall.Linkat(c.rootFd, oldParentRel, c.rootFd, newParentRel, 0)
	default:
		return err
	}
}

func (c *cache) createHierarchy() error {
	for prefix := range c.hierarchy.DFS().Run() {
		err := syscall.Mkdirat(c.rootFd, prefix, dirCreateMode)
		if err != nil {
			if err == os.ErrExist || errors.Is(err, os.ErrExist) {
				continue
			}
			return fmt.Errorf("Failed to create fd=%d basedir=%s path=%s: err=%w", c.rootFd, c.hierarchy.Basedir(), prefix, err)
		}
	}
	return nil
}

func (c *cache) cacheHierarchy() error {
	c.latch.Lock()
	defer c.latch.Unlock()

	for prefix := range c.hierarchy.RelPathIterator("").Run() {
		strippedPrefix := strings.Replace(prefix, "/", "", -1)
		idx := c.prefixToIndex(strippedPrefix)
		fd, err := syscall.Openat(c.rootFd, prefix, dirOpenFlags, dirCreateMode)
		if err != nil {
			return fmt.Errorf("Failed to preload fd=%d basedir=%s path=%s: err=%w", c.rootFd, c.hierarchy.Basedir(), prefix, err)
		} else {
			c.fdCache[idx] = fd
		}
	}

	return nil
}

func (c *cache) prefixToIndex(prefix string) int {
	i, _ := strconv.ParseInt(prefix, 16, 31)
	return int(i)
}

func (c *cache) parentFD(filename string) int {
	prefix := c.hierarchy.PrefixStripped(filename)
	idx := c.prefixToIndex(prefix)
	fd := c.fdCache[idx]
	return fd
}
