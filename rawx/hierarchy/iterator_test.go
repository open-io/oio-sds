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

import "testing"

func TestMarker(t *testing.T) {
	expect := func(src string, w, d uint, ok string) {
		m := markerToLeveledPath(src, w, d)
		if m != ok {
			t.Fatalf("marker=%s expected=%s actual=%s", src, ok, m)
		}
	}
	expect("01234567", 2, 3, "01/23/45")
	expect("01/23/45", 2, 3, "01/23/45")
	expect("01/23/45/", 2, 3, "01/23/45")
	expect("01/23/45/6", 2, 3, "01/23/45")

	// You need to know what you feed.
	// Either pass a well-formed path, or a chunk_id.
	// But be consistent with the path and have it respecting the width/depth config
	expect("01/23/0123456", 2, 3, "01/23/01")
	expect("01/2/3456", 2, 3, "01/23/45")

	expect("012", 2, 3, "01/2")
	expect("01/2", 2, 3, "01/2")
	expect("01/23", 2, 3, "01/23")
	expect("01/23/", 2, 3, "01/23")
}

func ensureMonotonic(t *testing.T, it PathIterator, expected int) {
	last := ""
	count := 0
	for x := range it.Run() {
		//t.Logf("last=%s x=%s count=%d", last, x, count)
		if x == last {
			t.Fatalf("dupplicated items %s", x)
		}
		if x <= last {
			t.Fatalf("non monotonic increasing last=%s current=%s", last, x)
		}
		last = x
		count++
	}
	if count != expected {
		t.Fatalf("count mismatch: got %d expected %d", count, expected)
	}
}

func TestIteratorDFS_1_1(t *testing.T) { ensureMonotonic(t, NewDFS(1, 1), 16) }
func TestIteratorDFS_2_1(t *testing.T) { ensureMonotonic(t, NewDFS(2, 1), 256) }
func TestIteratorDFS_1_2(t *testing.T) { ensureMonotonic(t, NewDFS(1, 2), 16+256) }
func TestIteratorDFS_2_2(t *testing.T) { ensureMonotonic(t, NewDFS(2, 2), 65536+256) }
func TestIteratorDFS_3_1(t *testing.T) { ensureMonotonic(t, NewDFS(3, 1), 4096) }
func TestIteratorDFS_1_3(t *testing.T) { ensureMonotonic(t, NewDFS(1, 3), 4096+256+16) }

func TestIteratorPrefix_1_1(t *testing.T) { ensureMonotonic(t, NewPrefixIterator(1, 1), 16) }
func TestIteratorPrefix_2_1(t *testing.T) { ensureMonotonic(t, NewPrefixIterator(2, 1), 256) }
func TestIteratorPrefix_1_2(t *testing.T) { ensureMonotonic(t, NewPrefixIterator(1, 2), 256) }
func TestIteratorPrefix_2_2(t *testing.T) { ensureMonotonic(t, NewPrefixIterator(2, 2), 65536) }
func TestIteratorPrefix_3_1(t *testing.T) { ensureMonotonic(t, NewPrefixIterator(3, 1), 4096) }
func TestIteratorPrefix_1_3(t *testing.T) { ensureMonotonic(t, NewPrefixIterator(1, 3), 4096) }

func TestIteratorRelPath_1_1(t *testing.T) { ensureMonotonic(t, NewRelPathIterator("", 1, 1), 16) }
func TestIteratorRelPath_2_1(t *testing.T) { ensureMonotonic(t, NewRelPathIterator("", 2, 1), 256) }
func TestIteratorRelPath_1_2(t *testing.T) { ensureMonotonic(t, NewRelPathIterator("", 1, 2), 256) }
func TestIteratorRelPath_2_2(t *testing.T) { ensureMonotonic(t, NewRelPathIterator("", 2, 2), 65536) }
func TestIteratorRelPath_3_1(t *testing.T) { ensureMonotonic(t, NewRelPathIterator("", 3, 1), 4096) }
func TestIteratorRelPath_1_3(t *testing.T) { ensureMonotonic(t, NewRelPathIterator("", 1, 3), 4096) }
