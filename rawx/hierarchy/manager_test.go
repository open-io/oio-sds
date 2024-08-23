// OpenIO SDS Go rawx
// Copyright (C) 2024 OVH SAS
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
	"os"
	"testing"

	syscall "golang.org/x/sys/unix"
)

type ManagerTestFunc func(*testing.T, FDManager, Hierarchy)

func testManager(t *testing.T, width, depth uint, cb ManagerTestFunc) {
	basedir, err := os.MkdirTemp("", "test-hierarchy")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("basedir: %s", basedir)
	//defer os.RemoveAll(basedir)

	h := NewHierarchy(basedir, width, depth)
	m := NewFDManager(h)
	defer m.Close()

	t.Log("init")
	if err := m.Init(); err != nil {
		t.Fatal(err)
	}

	cb(t, m, h)
}

func testManagerInit(t *testing.T, width, depth uint) {
	testManager(t, width, depth, func(*testing.T, FDManager, Hierarchy) {})
}

func TestManager_1_1(t *testing.T) { testManagerInit(t, 1, 1) }
func TestManager_1_2(t *testing.T) { testManagerInit(t, 1, 2) }
func TestManager_1_3(t *testing.T) { testManagerInit(t, 1, 3) }
func TestManager_3_1(t *testing.T) { testManagerInit(t, 3, 1) }
func TestManager_2_1(t *testing.T) { testManagerInit(t, 2, 1) }
func TestManager_2_2(t *testing.T) { testManagerInit(t, 2, 2) }

func TestManager_Cycle(t *testing.T) {
	testManager(t, 1, 2, func(t *testing.T, m FDManager, h Hierarchy) {
		var err error
		fd := -1
		name := "AAAA"

		// must work
		fd, err = m.Open(name, syscall.O_CREAT|syscall.O_EXCL|syscall.O_NONBLOCK|syscall.O_NOATIME|syscall.O_WRONLY, 0644)
		defer syscall.Close(fd)
		if err != nil {
			t.Fatal(err)
		}

		err = m.Access("AAAA", syscall.F_OK)
		if err != nil {
			t.Fatalf("failed to access fresh file: %s", err)
		}

		fd, err = m.Open("AAAA", syscall.O_NONBLOCK|syscall.O_NOATIME|syscall.O_RDONLY, 0)
		defer syscall.Close(fd)
		if err != nil {
			t.Fatalf("failed to open(RO) file: %s", err)
		}

		// must fail
		fd, err = m.Open(name, syscall.O_CREAT|syscall.O_EXCL|syscall.O_NONBLOCK|syscall.O_NOATIME|syscall.O_WRONLY, 0644)
		defer syscall.Close(fd)
		if err == nil {
			t.Fatalf("second create unexpectedly succeeded")
		}

		err = m.Access("AAAA", syscall.F_OK)
		if err != nil {
			t.Fatalf("failed to access fresh file: %s", err)
		}

		fd, err = m.Open("AAAA", syscall.O_NONBLOCK|syscall.O_NOATIME|syscall.O_RDONLY, 0)
		defer syscall.Close(fd)
		if err != nil {
			t.Fatalf("failed to open(RO) file: %s", err)
		}

		// first delete must succeed
		err = m.Unlink(name)
		if err != nil {
			t.Fatal(err)
		}

		err = m.Access("AAAA", syscall.F_OK)
		if err == nil {
			t.Fatalf("unexpectedly succeeded to access freshly deleted file: %s", err)
		}

		fd, err = m.Open("AAAA", syscall.O_NONBLOCK|syscall.O_NOATIME|syscall.O_RDONLY, 0)
		defer syscall.Close(fd)
		if err == nil {
			t.Fatalf("unexpectedly success to open(RO) file: %s", err)
		}

		// second delete must fail
		err = m.Unlink(name)
		if err == nil {
			t.Fatalf("second unlink unexpectedly succeeded")
		}
	})
}

func TestManager_Link(t *testing.T) {
	testManager(t, 1, 2, func(t *testing.T, m FDManager, h Hierarchy) {
		var err error
		fd := -1
		name := "AAAAA"

		fd, err = m.Open(name, syscall.O_CREAT|syscall.O_EXCL|syscall.O_NONBLOCK|syscall.O_NOATIME|syscall.O_WRONLY, 0644)
		if fd <= 0 || err != nil {
			t.Fatal(err)
		}

		err = m.Link(name, "BBBBB")
		if err != nil {
			t.Fatal(err)
		}
		err = m.Access("BBBBB", syscall.F_OK)
		if err != nil {
			t.Fatalf("failed to access fresh file: %s", err)
		}

		err = m.Link(name, "BBBBB")
		if err == nil {
			t.Fatal("unexpectedly succeeded to link at an existing location")
		}
		err = m.Access("BBBBB", syscall.F_OK)
		if err != nil {
			t.Fatalf("failed to access fresh file: %s", err)
		}

		err = m.Link(name, "AABBB")
		if err != nil {
			t.Fatal(err)
		}
		err = m.Access("AABBB", syscall.F_OK)
		if err != nil {
			t.Fatalf("failed to access fresh file: %s", err)
		}

	})
}
