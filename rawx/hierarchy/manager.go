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
	DirOpenFlags = syscall.O_PATH | syscall.O_DIRECTORY | syscall.O_NOATIME | syscall.O_CLOEXEC | syscall.O_NONBLOCK | syscall.O_RDWR
)

const (
	DirCreateMode = 0755
)

type FDManager interface {
	io.Closer
	Init() error

	Locate(name string) *Location
	Parent(path string, flags int, mode uint32) (int, error)
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
	c.rootFd, err = syscall.Open(c.hierarchy.Basedir(), DirOpenFlags, 0)
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

func (c *cache) Locate(name string) *Location {
	c.latch.RLock()
	defer c.latch.RUnlock()

	loc := &Location{
		FdBase:        c.parentFD(name),
		relPath:       name,
		PathParentAbs: c.hierarchy.PathAbs(name),
	}

	if loc.FdBase < 0 {
		loc.FdBase = c.rootFd
		loc.relPath = c.hierarchy.PathRel(name)
	}

	return loc
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

func (c *cache) createHierarchy() error {
	for prefix := range c.hierarchy.DFS().Run() {
		err := syscall.Mkdirat(c.rootFd, prefix, DirCreateMode)
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
		fd, err := syscall.Openat(c.rootFd, prefix, DirOpenFlags, DirCreateMode)
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
