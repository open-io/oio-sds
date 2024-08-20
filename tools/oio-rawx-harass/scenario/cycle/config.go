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

	"github.com/google/uuid"
	"openio-sds/tools/oio-rawx-harass/config"
	"openio-sds/tools/oio-rawx-harass/scenario"
)

type Config struct {
	// Concurrency management
	NbWorkers uint

	NbScenarios uint

	// Configuration flags that will alter the behavioral flags here-above
	NoGet bool
	NoDel bool
}

func (cfg *Config) Build(ctx context.Context, sz *config.SizesConfiguration, tgt *config.RawxTargets) (scenario.Runnable, error) {
	pop := &population{
		AbstractPopulation: scenario.AbstractPopulation{
			Id: uuid.NewString(),
		},

		cfg:     *cfg,
		targets: tgt,

		nextStepAfterPUT: stepGet,
		nextStepAfterGET: stepDelete,
		nextStepAfterDEL: stepPut,
		scenarios:        make([]Behavior, 0),
	}

	if cfg.NoGet && cfg.NoDel {
		pop.nextStepAfterPUT = stepPut
	} else if cfg.NoGet {
		pop.nextStepAfterPUT = stepDelete
	} else if cfg.NoDel {
		pop.nextStepAfterGET = stepPut
	}

	pop.generator = func() Behavior {
		return Behavior{
			step:             stepPut,
			globalIndex:      0,
			nextStepAfterPUT: pop.nextStepAfterPUT,
			nextStepAfterGET: pop.nextStepAfterGET,
			nextStepAfterDEL: pop.nextStepAfterDEL,
		}
	}

	return pop, nil
}
