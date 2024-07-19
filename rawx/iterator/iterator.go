package iterator

import (
	"fmt"
	"strings"
)

const letters = "0123456789ABCDEF"

type PathIterator struct {
	markerPath string
	width      uint
	depth      uint
	started    bool
}

func NewPathIterator(marker string, width, depth uint) *PathIterator {
	return &PathIterator{
		markerPath: markerToLeveledPath(marker, width, depth),
		width:      width,
		depth:      depth,
		started:    false,
	}
}

func (pi *PathIterator) lvl(pfx string, width, depth uint, out chan string) {
	if depth <= 0 {
		if !pi.started {
			pi.started = pfx >= pi.markerPath
		}
		if pi.started {
			out <- pfx
		}
	} else {
		if width > 1 {
			for _, c := range letters {
				pi.lvl(pfx+string(c), width-1, depth, out)
			}
		} else {
			if depth > 1 { // Avoid producing
				for _, c := range letters {
					pi.lvl(pfx+string(c)+"/", pi.width, depth-1, out)
				}
			} else {
				for _, c := range letters {
					pi.lvl(pfx+string(c), pi.width, depth-1, out)
				}
			}
		}
	}
}

func (pi *PathIterator) Run() chan string {
	fmt.Println("###", pi.markerPath, pi.width, pi.depth)
	out := make(chan string, 64)
	go func() {
		pi.lvl("", pi.width, pi.depth, out)
		close(out)
	}()
	return out
}

// Returns "AA/BB/CC" from ("AABBCCDD", 2, 3)
func markerToLeveledPath(marker string, width, depth uint) string {
	return strings.Join(markerToLevels(marker, width, depth), "/")
}

// Returns ["AA","BB","CC"] from ("AABBCCDD", 2, 3)
// Also accepts a path as a marker,
func markerToLevels(marker string, width, depth uint) []string {
	levels := make([]string, 0)
	w := uint(0)
	d := uint(0)
	buf := strings.Builder{}
	// Sanitize the marker, to relative paths as well as chunk_id
	marker = strings.Replace(marker, "/", "", -1)
	for _, c := range marker {
		buf.WriteRune(c)
		w++
		if w >= width {
			w = 0
			d++
			levels = append(levels, buf.String())
			buf.Reset()
			if d >= depth {
				break
			}
		}
	}
	return levels
}
