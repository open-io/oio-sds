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
	"container/heap"
	"context"
	"errors"
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

// population of behaviors currently being run
type population struct {
	scenario.AbstractPopulation

	config  Config
	targets *config.RawxTargets
	// Weight is the cumulated weight for that size slot
	accumulatedSizes distribution.Int64Histogram

	scenarios           utils.ScenarioHeap
	requestedCreations  chan bool
	successfulCreations chan *Behavior
	failedCreations     chan *Behavior

	generator ScenarioGenerator
}

const (
	batchSize = 32
)

func (pop *population) Warmup(ctx context.Context, stats *client.Stats) error {
	if stats == nil {
		return errors.New("Missing stats")
	}

	groupWarmup, ctx := errgroup.WithContext(ctx)
	if pop.config.MaxWorkers > 0 {
		groupWarmup.SetLimit(pop.config.MaxWorkers)
	} else {
		groupWarmup.SetLimit(4)
	}

	progress := utils.NewProgress(time.Now(), pop.Id)

	pop.Log(ctx).WithFields(log.Fields{
		"targets": pop.targets.Debug(),
		"count":   pop.config.WarmupChunks,
	}).Debugf("warmup starting %+v", pop)

	// Creation of chunks
	for i := int64(0); i < pop.config.WarmupChunks; i++ {
		clock := time.Now()
		s := pop.generator(clock)
		s.Refresh(pop.targets)
		pop.refreshDeadline(time.Now(), s)
		groupWarmup.Go(func() error {
			if e, _, _ := s.Put(stats, pop.targets, s.size); e != nil {
				pop.LogS(ctx, clock, s).WithError(e).Debug("put")
			} else {
				atomic.AddUint64(&progress.TotalPut, 1)
			}
			return nil
		})
		s.step = stepReady
		heap.Push(&pop.scenarios, s)

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

func (pop *population) Run(ctx context.Context, stats *client.Stats) error {
	if stats == nil {
		return errors.New("Missing stats")
	}

	pop.Log(ctx).WithFields(log.Fields{
		"targets": pop.targets.Debug(),
		"put":     pop.config.AverageCreationFrequency,
		"get":     pop.config.AverageGetFrequency,
		"life":    pop.config.LifeExpectancy,
		"lifeDev": pop.config.LifeDeviation,
	}).Debug("stress starting")

	// Trigger chunk creations
	go func(ctx context.Context) {
		// TODO(jfs): Poisson would be better here
		interval := time.Duration(float64(time.Second) / pop.config.AverageCreationFrequency)
		ticker := time.NewTicker(interval)
		done := ctx.Done()

		pop.Log(ctx).WithField("interval", interval).Debug("trigger starting")

	LOOP:
		for {
			select {
			case <-done:
				break LOOP
			case <-ticker.C:
				pop.requestedCreations <- true
			}
		}
		pop.Log(ctx).Debug("trigger exiting")
	}(ctx)

	// We bound the concurrency of the stress tool
	groupRun, ctx := errgroup.WithContext(ctx)
	groupRun.SetLimit(pop.config.MaxWorkers)
	progress := utils.NewProgress(time.Now(), pop.Id)

	for ctx.Err() == nil {
		clock := time.Now()
		pop.consumeCreationEvents(ctx, clock, pop.generator)
		roundPut, roundGet, roundDel := pop.triggerOneBatch(ctx, stats, clock, groupRun)
		progress.TotalPut += roundPut
		progress.TotalGet += roundGet
		progress.TotalDel += roundDel

		progress.PrintPeriodically(ctx, clock)

		time.Sleep(100 * time.Millisecond)
	}

	if e := groupRun.Wait(); e != nil {
		pop.Log(ctx).WithError(e).Warn("worker error")
	}

	progress.Print(ctx, time.Now())

	pop.Log(ctx).Debug("stress exiting")
	return nil
}

func (pop *population) Cleanup(ctx context.Context, stats *client.Stats) error {
	if stats == nil {
		return errors.New("Missing stats")
	}

	if !pop.config.Cleanup {
		pop.Log(ctx).Debug("cleanup skipped")
		return nil
	}

	pop.Log(ctx).Debug("cleanup starting")

	groupTail, ctx := errgroup.WithContext(ctx)
	groupTail.SetLimit(pop.config.MaxWorkers)

	for pop.scenarios.Len() > 0 {
		clock := time.Now()

		pop.consumeCreationEvents(ctx, clock, pop.generator)

		x := heap.Pop(&pop.scenarios)
		if x == nil {
			break
		}
		s := x.(*Behavior)

		groupTail.Go(func() error {
			for s.refcount.Load() > 0 {
				// This should never happen since all the GET workers are now shut down
				time.Sleep(100 * time.Millisecond)
			}
			s.Del(stats, pop.targets)
			return nil
		})
		pop.LogS(ctx, clock, s).Trace("delete")
	}

	pop.Log(ctx).Debug("cleanup exiting")
	return nil
}

func (pop *population) consumeCreationEvents(ctx context.Context, clock time.Time, generator ScenarioGenerator) {
	// non-blocking polling of elements in place
	for ctx.Err() == nil {
		select {
		case s := <-pop.successfulCreations:
			s.step = stepReady
			pop.refreshDeadline(clock, s)
			pop.scenarios.Push(s)
			heap.Push(&pop.scenarios, s)
			pop.LogS(ctx, clock, s).WithField("status", "ok").Trace("created")

		case s := <-pop.failedCreations:
			pop.LogS(ctx, clock, s).WithField("status", "error").Info("creation failed")

		case <-pop.requestedCreations:
			s := generator(clock)
			s.Refresh(pop.targets)
			pop.LogS(ctx, clock, s).Trace("creation requested")
			pop.scenarios.Push(s)
		default:
			return
		}
	}
}

func (pop *population) triggerOneBatch(ctx context.Context, stats *client.Stats, clock time.Time, group *errgroup.Group) (uint64, uint64, uint64) {
	var started, fetched, deleted uint64
LOOP:
	for i := 0; pop.scenarios.Len() > 0 && ctx.Err() == nil && i < batchSize; i++ {

		x := heap.Pop(&pop.scenarios)
		if x == nil {
			break
		}
		s := x.(*Behavior)

		if clock.Before(s.GetPriority()) {
			heap.Push(&pop.scenarios, s)
			break
		}

		switch s.step {
		case stepIdle:
			spawned := group.TryGo(func() error {
				if e, _, _ := s.Put(stats, pop.targets, s.size); e != nil {
					pop.failedCreations <- s
				} else {
					pop.successfulCreations <- s
				}
				return nil
			})
			if spawned {
				pop.LogS(ctx, clock, s).Trace("create")
				started++
			} else {
				break LOOP
			}

		case stepReady:
			if clock.After(s.deadlineDeletion) {
				spawned := group.TryGo(func() error {
					for s.refcount.Load() > 0 {
						time.Sleep(100 * time.Millisecond)
					}
					s.Del(stats, pop.targets)
					return nil
				})
				if spawned {
					deleted++
				} else {
					heap.Push(&pop.scenarios, s)
					break LOOP
				}
			} else {
				group.Go(func() error {
					s.refcount.Add(1)
					defer s.refcount.Add(^uint32(0))
					if e, _, _ := s.Get(stats, pop.targets); e != nil {
						pop.LogS(ctx, clock, s).WithError(e).Info("get failed")
					}
					return nil
				})
				fetched++
				pop.refreshDeadline(clock, s)
				heap.Push(&pop.scenarios, s)
			}
		}
	}

	return started, fetched, deleted
}

func (pop *population) refreshDeadline(clock time.Time, s *Behavior) {
	// TODO(jfs): also, the application of the Poisson law would make sense here
	interval := time.Duration(float64(time.Second) / pop.config.AverageGetFrequency)
	s.deadlineGet = clock.Add(interval)
}

// Generate a log event for the given Behavior
func (pop *population) LogS(ctx context.Context, clock time.Time, s *Behavior) *log.Entry {
	return pop.LogT(ctx, clock).WithField("_id", s.globalIndex)
}
