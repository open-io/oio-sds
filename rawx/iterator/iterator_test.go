package iterator

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
