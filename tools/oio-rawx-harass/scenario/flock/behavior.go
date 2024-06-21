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

package flock

import (
	"sync/atomic"
	"time"

	"openio-sds/tools/oio-rawx-harass/client"
)

type Step uint32

const (
	// to be created
	stepIdle Step = iota
	// to be fetched or deleted
	stepReady Step = iota
)

type Behavior struct {
	client.RawxClient

	// Position in the heap used to tell which scenario triggers next
	heapIndex int

	// General salt set at the creation of the
	globalIndex uint

	// when the next download should be triggered
	deadlineGet time.Time

	// When the object will cease to exist
	deadlineDeletion time.Time

	refcount atomic.Uint32

	size int64

	step Step
}

func (rc *Behavior) GetPriority() time.Time {
	if rc.deadlineGet.Before(rc.deadlineDeletion) {
		return rc.deadlineGet
	}
	return rc.deadlineDeletion
}

func (rc *Behavior) GetIndex() int {
	return rc.heapIndex
}

func (rc *Behavior) SetIndex(i int) {
	rc.heapIndex = i
}
