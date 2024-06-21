// OpenIO SDS oio-rawx-harass
// Copyright (C) 2019-2020 OpenIO SAS
// Copyright (C) 2021-2024 OVH SAS
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

package utils

import (
	"math/rand"
	"sort"
)

type SizeSlot struct {
	Size   int64 `yaml:"size"`
	Weight int64 `yaml:"weight"`
}

type SizeHistograms []SizeSlot

// Implements sort.Interface
func (s SizeHistograms) Len() int {
	return len(s)
}

// Implements sort.Interface
func (s SizeHistograms) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Implements sort.Interface
func (s SizeHistograms) Less(i, j int) bool {
	return s[i].Size < s[j].Size
}

func NewSizeHistograms(sizes []SizeSlot) SizeHistograms {
	sizeHistograms := make(SizeHistograms, len(sizes))
	sizeHistograms.Init(sizes)
	return sizeHistograms
}

func (s SizeHistograms) Init(sizes []SizeSlot) {
	copy(s, sizes)
	sort.Sort(s)
	total := int64(0)
	for i, _ := range s {
		total += (s)[i].Weight
		(s)[i].Weight = total
	}
}

func (s SizeHistograms) Poll() int64 {
	boundary := s[len(s)-1].Weight
	needle := rand.Int63n(boundary)
	for i, x := range s {
		if x.Weight > needle { // we have the right slot
			prev := int64(0)
			if i > 0 {
				prev = s[i-1].Size
			}
			return prev + rand.Int63n(x.Size-prev)
		}
	}
	panic("plop")
}
