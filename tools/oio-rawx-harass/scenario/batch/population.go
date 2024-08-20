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

package batch

import (
	"context"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"openio-sds/tools/oio-rawx-harass/client"
	"openio-sds/tools/oio-rawx-harass/config"
	"openio-sds/tools/oio-rawx-harass/distribution"
	"openio-sds/tools/oio-rawx-harass/scenario"
	"openio-sds/tools/oio-rawx-harass/utils"
)

type Behavior struct {
	client.RawxClient

	// General salt set at the creation of the
	globalIndex uint

	refcount atomic.Uint32

	size int64
}

type opResult struct {
	pop *targetPopulation
	s   *Behavior
	err error
}

type loadProfile struct {
	duration   time.Duration
	poissonGet distribution.PoissonDistribution
	poissonDel distribution.PoissonDistribution
	poissonPut distribution.PoissonDistribution
}

// population of behaviors currently being run
type population struct {
	scenario.AbstractPopulation

	config           Config
	targets          *config.RawxTargets
	accumulatedSizes distribution.Int64Histogram

	generator ScenarioGenerator

	scenarios []*targetPopulation

	requestedPut chan bool
	requestedDel chan bool
	requestedGet chan bool

	created chan opResult
	deleted chan opResult
	getted  chan opResult

	// cumulated probabilities of
	loads []*loadProfile
}

func (pop *population) warmupOnly(ctx context.Context, stats *client.Stats) error {
	pop.Log(ctx).WithFields(log.Fields{
		"targets": pop.targets,
		"count":   pop.config.WarmupChunks,
	}).Debug("warmup starting")

	groupWarmup, ctx := errgroup.WithContext(ctx)
	if pop.config.MaxWorkers > 0 {
		groupWarmup.SetLimit(pop.config.MaxWorkers)
	} else {
		groupWarmup.SetLimit(4)
	}

	progress := utils.NewProgress(time.Now(), pop.Id)

	// Creation of chunks
	for i := int64(0); i < pop.config.WarmupChunks; i++ {
		clock := time.Now()
		s := pop.generator(clock)
		s.Refresh(pop.targets)
		groupWarmup.Go(func() error {
			err, _, _ := s.Put(stats, pop.targets, s.size)
			if err != nil {
				atomic.AddUint64(&progress.TotalErr, 1)
				pop.log2(ctx, s).WithFields(s.LogFields(pop.targets)).WithError(err).Info("PUT failed")
			} else {
				s.Persist(pop.targets)
			}
			return nil
		})
		progress.TotalPut++

		p := pop.resolveTarget(s.Rawx(pop.targets))
		p.scenarios = append(p.scenarios, s)
		progress.PrintPeriodically(ctx, clock)
	}

	err := groupWarmup.Wait()

	progress.Print(ctx, time.Now())

	pop.Log(ctx).WithFields(log.Fields{
		"targets": pop.targets.Debug(),
		"count":   pop.config.WarmupChunks,
	}).WithError(err).Debug("warmup exiting")
	return err

}

func (pop *population) Warmup(ctx context.Context, stats *client.Stats) error {

	if pop.config.Discover {
		if err := pop.discoverAllRawx(ctx); err != nil {
			return err
		}
	}

	return pop.warmupOnly(ctx, stats)
}

func (pop *population) trigger(ctx0 context.Context) error {
	for _, l := range pop.loads {
		g, ctx0 := errgroup.WithContext(ctx0)
		g.SetLimit(3)

		// Maybe interrupt early the stress with that load profile
		var ctx context.Context
		var cancel context.CancelFunc
		if l.duration > 0 {
			ctx, cancel = context.WithTimeout(ctx0, l.duration)
		} else {
			ctx, cancel = context.WithCancel(ctx0)
		}

		pop.Log(ctx).WithFields(log.Fields{
			"put": l.poissonPut.Lambda(),
			"get": l.poissonGet.Lambda(),
			"del": l.poissonDel.Lambda(),
		}).Info("load start")

		g.Go(func() error {
			utils.AperiodicTicker(ctx, pop.requestedPut, func() int {
				return l.poissonPut.Poll()
			})
			return nil
		})
		g.Go(func() error {
			utils.AperiodicTicker(ctx, pop.requestedGet, func() int {
				return l.poissonGet.Poll()
			})
			return nil
		})
		g.Go(func() error {
			utils.AperiodicTicker(ctx, pop.requestedDel, func() int {
				return l.poissonDel.Poll()
			})
			return nil
		})
		e := g.Wait()
		cancel()
		if e != nil {
			return e
		}

		pop.Log(ctx).WithFields(log.Fields{
			"put": l.poissonPut.Lambda(),
			"get": l.poissonGet.Lambda(),
			"del": l.poissonDel.Lambda(),
		}).Info("load end")
	}

	close(pop.requestedPut)
	close(pop.requestedGet)
	close(pop.requestedDel)
	return nil
}

func (pop *population) Run(ctx context.Context, stats *client.Stats) error {
	if pop.config.MaxWorkers <= 0 {
		pop.config.MaxWorkers = 32
	}

	pop.Log(ctx).WithField("targets", pop.targets.Debug()).Debug("stress starting")

	// We bound the concurrency of the stress tool
	groupRun, ctx := errgroup.WithContext(ctx)
	groupRun.SetLimit(pop.config.MaxWorkers + 1)
	groupRun.Go(func() error {
		pop.trigger(ctx)
		return nil
	})

	progress := utils.NewProgress(time.Now(), pop.Id)

LOOP:
	for ctx.Err() == nil {

	DRAIN:
		for ctx.Err() == nil {
			select {
			case <-ctx.Done():
				break LOOP
			case op := <-pop.created:
				pop.onPutResult(ctx, &progress, &op)
			case op := <-pop.deleted:
				pop.onDelResult(ctx, &progress, &op)
			case op := <-pop.getted:
				pop.onGetResult(ctx, &progress, &op)
			default:
				break DRAIN
			}
		}

		clock := time.Now()

		select {
		case <-ctx.Done():
			break LOOP

		case op := <-pop.created:
			pop.onPutResult(ctx, &progress, &op)

		case op := <-pop.deleted:
			pop.onDelResult(ctx, &progress, &op)

		case op := <-pop.getted:
			pop.onGetResult(ctx, &progress, &op)

		case _, ok := <-pop.requestedPut:
			if !ok {
				break LOOP
			}
			s := pop.generator(clock)
			s.Refresh(pop.targets)
			p := pop.resolveTarget(s.Rawx(pop.targets))
			if groupRun.TryGo(func() error {
				e, _, _ := s.Put(stats, pop.targets, s.size)
				pop.created <- opResult{p, s, e}
				return nil
			}) {
				progress.TotalPut++
			}

		case _, ok := <-pop.requestedGet:
			if !ok {
				break LOOP
			}
			if p, s := pop.choose(); s != nil {
				if groupRun.TryGo(func() error {
					s.refcount.Add(1)
					defer s.refcount.Add(^uint32(0))
					e, _, _ := s.Get(stats, pop.targets)
					pop.getted <- opResult{p, s, e}
					return nil
				}) {
					progress.TotalGet++
				}
			}

		case _, ok := <-pop.requestedDel:
			if !ok {
				break LOOP
			}
			if p, s := pop.steal(false); s != nil {
				if groupRun.TryGo(func() error {
					for s.refcount.Load() > 0 {
						time.Sleep(100 * time.Millisecond)
					}
					e, _ := s.Del(stats, pop.targets)
					pop.getted <- opResult{p, s, e}
					return nil
				}) {
					progress.TotalDel++
				}
			}
		}

		progress.PrintPeriodically(ctx, clock)
	}

	pop.Log(ctx).Debug("stress tearing down")

	if e := groupRun.Wait(); e != nil {
		pop.Log(ctx).WithError(e).Warn("worker error")
	}

	pop.Log(ctx).Debug("stress workers exited")

	// the 3 trigger channels have been close by their generator function
	close(pop.created)
	close(pop.deleted)
	close(pop.getted)

	for op := range pop.getted {
		pop.onGetResult(ctx, &progress, &op)
	}
	for op := range pop.created {
		pop.onPutResult(ctx, &progress, &op)
	}
	for op := range pop.deleted {
		pop.onDelResult(ctx, &progress, &op)
	}

	progress.Print(ctx, time.Now())

	pop.Log(ctx).Debug("stress exiting")
	return nil
}

func (pop *population) Cleanup(ctx context.Context, stats *client.Stats) error {
	if !pop.config.Cleanup {
		pop.Log(ctx).Debug("cleanup skipped")
		return nil
	}

	pop.Log(ctx).Debug("cleanup starting")

	groupTail, ctx := errgroup.WithContext(ctx)
	groupTail.SetLimit(pop.config.MaxWorkers)

	for {
		p, s := pop.steal(false)
		if p == nil {
			break
		}
		groupTail.Go(func() error {
			for s.refcount.Load() > 0 {
				// This should never happen since all the GET workers are now shut down
				time.Sleep(100 * time.Millisecond)
			}
			e, _ := s.Del(stats, pop.targets)
			pop.deleted <- opResult{p, s, e}
			return nil
		})
		pop.log2(ctx, s).Trace("delete")
	}

	pop.Log(ctx).Debug("cleanup exiting")
	return nil
}

// Generate a log event for the given Behavior
func (pop *population) log2(ctx context.Context, s *Behavior) *log.Entry {
	return utils.LogT(ctx, time.Now()).WithField("_id", s.globalIndex)
}

func (pop *population) onPutResult(ctx context.Context, progress *utils.Progress, op *opResult) {
	if op.err == nil {
		op.s.Persist(pop.targets)
		op.pop.scenarios = append(op.pop.scenarios, op.s)
		pop.log2(ctx, op.s).WithField("status", "ok").Trace("created")
	} else {
		progress.TotalErr++
		pop.log2(ctx, op.s).WithField("status", "err").WithError(op.err).Warn("failed creation")
	}
}

func (pop *population) onGetResult(ctx context.Context, progress *utils.Progress, op *opResult) {
	if op.err != nil {
		progress.TotalErr++
		pop.log2(ctx, op.s).WithField("status", "err").WithError(op.err).Warn("failed get")
	}
}

func (pop *population) onDelResult(ctx context.Context, progress *utils.Progress, op *opResult) {
	if op.err == nil {
		op.s.Forget(pop.targets)
		pop.log2(ctx, op.s).WithField("status", "ok").Trace("deleted")
	} else {
		progress.TotalErr++
		pop.log2(ctx, op.s).WithField("status", "err").WithError(op.err).Warn("failed deletion")
		op.pop.scenarios = append(op.pop.scenarios, op.s)
	}
}
