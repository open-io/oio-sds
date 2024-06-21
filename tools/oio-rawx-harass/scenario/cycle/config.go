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
	"errors"
	log "github.com/sirupsen/logrus"
	"openio-sds/tools/oio-rawx-harass/client"
	"time"
)

type PopulationConfig struct {
	// Exit conditions
	Duration time.Duration

	// Concurrency management
	NbWorkers uint

	NbScenarios uint

	// Configuration flags that will alter the behavioral flags here-above
	NoGet bool
	NoDel bool
}

func (cfg *PopulationConfig) Run(ctx context.Context, tgt client.RawxTarget, stats *client.Stats) error {

	if len(tgt.RawxUrl) <= 0 {
		return errors.New("No RAWX specified")
	}

	pop := population{
		cfg:              *cfg,
		nextStepAfterPUT: stepGet,
		nextStepAfterGET: stepDelete,
		nextStepAfterDEL: stepPut,
	}

	if cfg.NoGet && cfg.NoDel {
		pop.nextStepAfterPUT = stepPut
	} else if cfg.NoGet {
		pop.nextStepAfterPUT = stepDelete
	} else if cfg.NoDel {
		pop.nextStepAfterGET = stepPut
	}

	log.WithFields(log.Fields{
		"targets":  tgt.RawxUrl,
		"afterPut": toString(pop.nextStepAfterPUT),
		"afterGet": toString(pop.nextStepAfterGET),
		"afterDel": toString(pop.nextStepAfterDEL),
	}).Debug("cycle")

	return pop.Run(ctx, &tgt, stats, func() Scenario {
		s := &Behavior{}
		s.nextStepAfterPUT = pop.nextStepAfterPUT
		s.nextStepAfterGET = pop.nextStepAfterGET
		s.nextStepAfterDEL = pop.nextStepAfterDEL
		return s
	})
}
