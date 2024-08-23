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
	"math"
	"path/filepath"
	"strings"
)

// Paths Computations around a filesystem hierarchy
type Hierarchy interface {
	Basedir() string
	// Return the number of prefixes
	CountPrefixes() uint64

	// XX/YY
	Prefix(filename string) string
	// XXYY
	PrefixStripped(filename string) string
	// XX/YY/XXYY123
	PathRel(filename string) string
	// /path/to/volume/XX/YY/XXYY123
	PathAbs(filename string) string
	// /path/to/volume/XX/YY
	ParentAbs(filename string) string

	// Leaf-only relative paths iterator (XX/YY)
	RelPathIterator(marker string) PathIterator
	// Leaf-only prefixes iterator (XXYY)
	PrefixIterator() PathIterator
	// Complete depth-first search iterator (XX, XX/YY)
	DFS() PathIterator
}

func NewHierarchy(basedir string, width, depth uint) Hierarchy {
	return &leveledHierarchy{
		basedir: basedir,
		width:   width,
		depth:   depth,
	}
}

type leveledHierarchy struct {
	basedir string
	width   uint
	depth   uint
}

func (h *leveledHierarchy) CountPrefixes() uint64 {
	return uint64(math.Pow(16, float64(h.width*h.depth)))
}

func (h *leveledHierarchy) Basedir() string {
	return h.basedir
}

func (h *leveledHierarchy) PrefixStripped(filename string) string {
	sb := strings.Builder{}
	h.computePrefix(&sb, filename, false)
	return sb.String()
}

func (h *leveledHierarchy) Prefix(filename string) string {
	sb := strings.Builder{}
	h.computePrefix(&sb, filename, true)
	return sb.String()
}

func (h *leveledHierarchy) PathRel(filename string) string {
	sb := strings.Builder{}
	h.computePathRel(&sb, filename)
	return sb.String()
}

func (h *leveledHierarchy) PathAbs(filename string) string {
	sb := strings.Builder{}
	sb.WriteString(h.basedir)
	sb.WriteRune(filepath.Separator)
	h.computePathRel(&sb, filename)
	return sb.String()
}

func (h *leveledHierarchy) ParentAbs(filename string) string {
	sb := strings.Builder{}
	sb.WriteString(h.basedir)
	sb.WriteRune(filepath.Separator)
	h.computePrefix(&sb, filename, true)
	return sb.String()
}

func (h *leveledHierarchy) RelPathIterator(marker string) PathIterator {
	return NewRelPathIterator(marker, h.width, h.depth)
}

func (h *leveledHierarchy) PrefixIterator() PathIterator {
	return NewPrefixIterator(h.width, h.depth)
}

func (h *leveledHierarchy) DFS() PathIterator {
	return NewDFS(h.width, h.depth)
}

func (h *leveledHierarchy) computePrefix(sb *strings.Builder, filename string, slashes bool) {
	for i := uint(0); i < h.depth; i++ {
		start := i * h.width
		if slashes && i > 0 {
			sb.WriteRune(filepath.Separator)
		}
		sb.WriteString(filename[start : start+h.width])
	}
}

func (h *leveledHierarchy) computePathRel(sb *strings.Builder, filename string) {
	h.computePrefix(sb, filename, true)
	sb.WriteRune(filepath.Separator)
	sb.WriteString(filename)
}
