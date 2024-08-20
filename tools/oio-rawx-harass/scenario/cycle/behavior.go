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

import (
	"context"

	"openio-sds/tools/oio-rawx-harass/client"
	"openio-sds/tools/oio-rawx-harass/config"
	"openio-sds/tools/oio-rawx-harass/utils"
)

const BufferSize = 65536

type Behavior struct {
	client.RawxClient

	globalIndex uint

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

// SetUp
func (rc *Behavior) SetUp(index uint) {
	rc.globalIndex = index
	rc.step = stepPut
}

// TearDown implements Scenario
func (rc *Behavior) TearDown(ctx context.Context, tgt *config.RawxTargets, st *client.Stats) {
	if rc.step == stepPut {
		return
	}
	if err, _ := rc.Del(st, tgt); err != nil {
		utils.Log(ctx).WithFields(rc.LogFields(tgt)).WithError(err).Info("DEL")
	}
	rc.step = stepPut
}

// Step implements Scenario
func (rc *Behavior) Step(ctx context.Context, tgt *config.RawxTargets, st *client.Stats) {
	switch rc.step {
	case stepPut:
		rc.Refresh(tgt)
		if err, _, _ := rc.Put(st, tgt, BufferSize); err == nil {
			rc.step = rc.nextStepAfterPUT
		} else {
			utils.Log(ctx).WithFields(rc.LogFields(tgt)).WithError(err).Info("PUT")
		}
	case stepGet:
		if err, _, _ := rc.Get(st, tgt); err == nil {
			rc.step = rc.nextStepAfterGET
		} else {
			utils.Log(ctx).WithFields(rc.LogFields(tgt)).Info("GET")
		}
	case stepDelete:
		if err, _ := rc.Del(st, tgt); err == nil {
			rc.step = rc.nextStepAfterDEL
		} else {
			utils.Log(ctx).WithFields(rc.LogFields(tgt)).WithError(err).Info("DEL")
		}
	}
}
