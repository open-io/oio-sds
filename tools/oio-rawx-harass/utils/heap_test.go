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
	"container/heap"
	"math/rand"
	"testing"
	"time"
)

const delayDeviation = 60.0 * float64(time.Second)
const averageDeviation = float64(60.0)

type MockScenario struct {
	heapIndex        int
	deadlineGet      time.Time
	deadlineDeletion time.Time
}

func (rc *MockScenario) GetPriority() time.Time {
	if rc.deadlineGet.Before(rc.deadlineDeletion) {
		return rc.deadlineGet
	}
	return rc.deadlineDeletion
}

func (rc *MockScenario) GetIndex() int { return rc.heapIndex }

func (rc *MockScenario) SetIndex(i int) { rc.heapIndex = i }

func TestHeapBig(t *testing.T) {
	r := rand.New(rand.NewSource(0))
	h := make(ScenarioHeap, 0)

	start := time.Now()
	pre := start
	delta := func(tag string) {
		now := time.Now()
		t.Logf("%s spent=%v %v", tag, (now.Sub(pre)).Milliseconds(), now)
		pre = now
	}
	delta("begin")
	for i := 0; i < 5000000; i++ {
		dev := averageDeviation + r.NormFloat64()*delayDeviation
		h = append(h, &MockScenario{
			deadlineGet:      start.Add(time.Duration(int64(dev))),
			deadlineDeletion: start.Add(5 * time.Minute),
		})
	}
	delta("full")
	heap.Init(&h)
	delta("sorted 1")
	heap.Init(&h)
	delta("sorted 2")
	heap.Init(&h)
	delta("sorted 3")
	for i := 0; i < 1000; i++ {
		x := heap.Pop(&h)
		if s, ok := x.(*MockScenario); !ok {
			t.Fatal("unexpected behavior")
		} else {
			s.deadlineGet.Add(time.Minute)
			heap.Push(&h, s)
		}
	}
	delta("done")
}
