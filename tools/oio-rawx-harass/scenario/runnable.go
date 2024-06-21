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
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"openio-sds/tools/oio-rawx-harass/client"
)

type RunnableBuilder interface {
	GetTargets() client.RawxTarget

	Build() (Runnable, error)
}

type Runnable interface {
	Warmup(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error

	Run(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error

	Cleanup(cx context.Context, tgt *client.RawxTarget, stats *client.Stats) error
}

// Run spawns a new stress for the given Runnable scenario, with a fresh stats holder, toward the given targets.
// The targets are explicitely passed bby value to avoid the list to be altered by another stress run.
// The dedicated stats are then returned.
func Run(ctx context.Context, tgt client.RawxTarget, pop Runnable, duration time.Duration) (err error, statsWarmup client.Stats, statsRun client.Stats, statsCleanup client.Stats) {
	log.Debug("Run")
	err = pop.Warmup(ctx, &tgt, &statsWarmup)
	if err == nil {
		ctxDeadline, cancel := context.WithTimeout(ctx, duration)
		defer cancel()
		err = pop.Run(ctxDeadline, &tgt, &statsRun)
	}
	if errCleanup := pop.Cleanup(ctx, &tgt, &statsCleanup); errCleanup != nil {
		if err == nil {
			err = errCleanup
		} else {
			log.Warnf("error at cleanup: %v", errCleanup)
		}
	}
	return err, statsWarmup, statsRun, statsCleanup
}

// RunAndPrint spawns a stress run and dumps a human-readable representation of the stats to the standard output
func RunAndPrint(ctx context.Context, tgt client.RawxTarget, pop Runnable, duration time.Duration) error {
	log.Debug("RunAndPrint")
	err, statsWarmup, statsRun, statsCleanup := Run(ctx, tgt, pop, duration)
	if err == nil {
		err = statsWarmup.WriteHuman("warmup", os.Stdout)
		err = statsRun.WriteHuman("stress", os.Stdout)
		err = statsCleanup.WriteHuman("cleanup", os.Stdout)
	}
	return err
}

// RunAndPrint spawns a stress run and dumps a human-readable representation of the stats to the standard output
func BuildAndRunAndPrint(ctx context.Context, tgt client.RawxTarget, builder RunnableBuilder, duration time.Duration) error {
	log.Debug("BuildAndRunAndPrint")
	if pop, err := builder.Build(); err != nil {
		return err
	} else {
		return RunAndPrint(ctx, tgt, pop, duration)
	}
}
