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

type LeafDirWalker func()

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

	// don't forget the tail
	if buf.Len() > 0 {
		levels = append(levels, buf.String())
		buf.Reset()
	}
	return levels
}
