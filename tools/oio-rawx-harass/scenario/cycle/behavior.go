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

package cycle

import "openio-sds/tools/oio-rawx-harass/client"

type Behavior struct {
	client.RawxClient

	// Managed by the controller
	step stepAction

	nextStepAfterPUT stepAction
	nextStepAfterGET stepAction
	nextStepAfterDEL stepAction
}

type stepAction uint

const (
	stepPut    stepAction = iota
	stepGet               = iota
	stepDelete            = iota
)

func toString(action stepAction) string {
	switch action {
	case stepPut:
		return "put"
	case stepGet:
		return "get"
	case stepDelete:
		return "del"
	default:
		return "?"
	}
}

// SetUp implements Scenario
func (rc *Behavior) SetUp(index uint) {
	rc.step = stepPut
}

// TearDown implements Scenario
func (rc *Behavior) TearDown() {
	if rc.step == stepPut {
		return
	}
}

// Step implements Scenario
func (rc *Behavior) Step(tgt *client.RawxTarget, st *client.Stats) {
	switch rc.step {
	case stepPut:
		rc.Refresh(tgt, rc.GetIndex())
		status, _ := rc.Put(tgt, st)
		if status/100 == 2 {
			rc.step = rc.nextStepAfterPUT
		}
	case stepGet:
		status, _ := rc.Get(tgt, st)
		if status/100 == 2 {
			rc.step = rc.nextStepAfterGET
		}
	case stepDelete:
		status := rc.Del(tgt, st)
		if status/100 == 2 {
			rc.step = rc.nextStepAfterDEL
		}
	}
}
