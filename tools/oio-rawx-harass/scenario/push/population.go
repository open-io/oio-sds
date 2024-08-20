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

package push

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"openio-sds/tools/oio-rawx-harass/client"
	"openio-sds/tools/oio-rawx-harass/config"
	"openio-sds/tools/oio-rawx-harass/distribution"
	"openio-sds/tools/oio-rawx-harass/scenario"
	"openio-sds/tools/oio-rawx-harass/utils"
)

// population of behaviors currently being run
type population struct {
	scenario.AbstractPopulation

	config           Config
	targets          *config.RawxTargets
	accumulatedSizes distribution.Int64Histogram
}

// A warmup phase has no sense in a Push scenario, that is destined to be a general warmup
// for another scenario.

func (pop *population) Run(ctx context.Context, stats *client.Stats) error {
	if stats == nil {
		return errors.New("Missing stats")
	}

	// We bound the concurrency of the stress tool
	groupRun, ctx := errgroup.WithContext(ctx)
	if pop.config.MaxWorkers > 0 {
		groupRun.SetLimit(pop.config.MaxWorkers)
	}

	progress := utils.NewProgress(time.Now(), pop.Id)

	for ctx.Err() == nil {
		groupRun.Go(func() error {
			sz := pop.accumulatedSizes.Poll()
			rx := client.RawxClient{}
			rx.Refresh(pop.targets)
			e, _, _ := rx.Put(stats, pop.targets, sz)
			if e == nil {
				e = rx.Persist(pop.targets)
			}
			if e != nil {
				pop.Log(ctx).WithError(e).WithFields(log.Fields{
					"chunk": rx.ChunkId(),
					"rx":    rx.Rawx(pop.targets),
					"size":  sz,
				}).Info("put")
			}
			return nil
		})
		progress.TotalPut++
		progress.PrintPeriodically(ctx, time.Now())
	}

	progress.Print(ctx, time.Now())
	return groupRun.Wait()
}
