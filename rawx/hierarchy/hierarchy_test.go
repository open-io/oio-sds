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
	"path/filepath"
	"testing"
)

func TestHierarchy_w1_d2(t *testing.T) {
	basedir, err := os.MkdirTemp("", "test-hierarchy")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(basedir)

	h := NewHierarchy(basedir, 1, 2)
	if h.Basedir() != basedir {
		t.Fatalf("basedir = %s; want %s", h.Basedir(), basedir)
	}

	ensure := func(got, expect string) {
		if got != expect {
			t.Fatalf("got = %s; expected %s", got, expect)
		}
	}

	ensure(h.PathAbs("ABCD"), filepath.Join(basedir, "A", "B", "ABCD"))
	ensure(h.PathRel("ABCD"), filepath.Join("A", "B", "ABCD"))
	ensure(h.Prefix("ABCD"), filepath.Join("A", "B"))
	ensure(h.PrefixStripped("ABCD"), "AB")
	ensure(h.ParentAbs("ABCD"), filepath.Join(basedir, "A", "B"))
}

func TestHierarchy_w2_d1(t *testing.T) {
	basedir, err := os.MkdirTemp("", "test-hierarchy")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(basedir)

	h := NewHierarchy(basedir, 2, 1)
	if h.Basedir() != basedir {
		t.Fatalf("basedir = %s; want %s", h.Basedir(), basedir)
	}

	ensure := func(got, expect string) {
		if got != expect {
			t.Fatalf("got = %s; expected %s", got, expect)
		}
	}

	ensure(h.PathAbs("ABCD"), filepath.Join(basedir, "AB", "ABCD"))
	ensure(h.PathRel("ABCD"), filepath.Join("AB", "ABCD"))
	ensure(h.Prefix("ABCD"), "AB")
	ensure(h.PrefixStripped("ABCD"), "AB")
	ensure(h.ParentAbs("ABCD"), filepath.Join(basedir, "AB"))
}

func TestHierarchy_w2_d2(t *testing.T) {
	basedir, err := os.MkdirTemp("", "test-hierarchy")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(basedir)

	h := NewHierarchy(basedir, 2, 2)
	if h.Basedir() != basedir {
		t.Fatalf("basedir = %s; want %s", h.Basedir(), basedir)
	}

	ensure := func(got, expect string) {
		if got != expect {
			t.Fatalf("got = %s; expected %s", got, expect)
		}
	}

	ensure(h.PathAbs("ABCDEF"), filepath.Join(basedir, "AB", "CD", "ABCDEF"))
	ensure(h.PathRel("ABCDEF"), filepath.Join("AB", "CD", "ABCDEF"))
	ensure(h.Prefix("ABCDEF"), filepath.Join("AB", "CD"))
	ensure(h.PrefixStripped("ABCDEF"), "ABCD")
	ensure(h.ParentAbs("ABCD"), filepath.Join(basedir, "AB", "CD"))
}
