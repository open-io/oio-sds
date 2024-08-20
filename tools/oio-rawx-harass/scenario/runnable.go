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

package scenario

import (
	"context"
	"errors"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"openio-sds/tools/oio-rawx-harass/client"
	"openio-sds/tools/oio-rawx-harass/config"
)

type RunnableBuilder interface {
	Build(ctx context.Context, sizes *config.SizesConfiguration, tgt *config.RawxTargets) (Runnable, error)
}

type Runnable interface {
	Warmup(ctx context.Context, stats *client.Stats) error

	Run(ctx context.Context, stats *client.Stats) error

	Cleanup(cx context.Context, stats *client.Stats) error
}

type Runner struct {
	pop   Runnable
	tgt   *config.RawxTargets
	sizes *config.SizesConfiguration
}

// Run spawns a new stress for the given Runnable scenario, with a fresh stats holder, toward the given targets.
// The targets are explicitely passed bby value to avoid the list to be altered by another stress run.
// The dedicated stats are then returned.
func (r *Runner) Run(ctx context.Context, duration time.Duration) (err error, statsWarmup client.Stats, statsRun client.Stats, statsCleanup client.Stats) {
	err = r.pop.Warmup(ctx, &statsWarmup)
	if err == nil {
		var ctxDeadline context.Context
		var cancel context.CancelFunc
		if duration > 0 {
			ctxDeadline, cancel = context.WithTimeout(ctx, duration)
		} else {
			ctxDeadline, cancel = context.WithCancel(ctx)
		}
		defer cancel()
		err = r.pop.Run(ctxDeadline, &statsRun)
	}
	if errCleanup := r.pop.Cleanup(ctx, &statsCleanup); errCleanup != nil {
		if err == nil {
			err = errCleanup
		} else {
			log.WithContext(ctx).Warnf("error at cleanup: %v", errCleanup)
		}
	}
	return err, statsWarmup, statsRun, statsCleanup
}

// RunAndPrint spawns a stress run and dumps a human-readable representation of the stats to the standard output
func (r *Runner) RunAndPrint(ctx context.Context, duration time.Duration) error {
	err, statsWarmup, statsRun, statsCleanup := r.Run(ctx, duration)
	if err == nil {
		err = statsWarmup.WriteHuman("warmup", os.Stdout)
		err = statsRun.WriteHuman("stress", os.Stdout)
		err = statsCleanup.WriteHuman("cleanup", os.Stdout)
	}
	return err
}

func NewRunner(ctx context.Context, builder RunnableBuilder, tgt *config.RawxTargets, sz *config.SizesConfiguration) (*Runner, error) {
	if tgt.Empty() {
		return nil, errors.New("No target configured")
	}

	if pop, err := builder.Build(ctx, sz, tgt); err != nil {
		return nil, err
	} else {
		return &Runner{
			pop:   pop,
			tgt:   tgt,
			sizes: sz,
		}, nil
	}
}
