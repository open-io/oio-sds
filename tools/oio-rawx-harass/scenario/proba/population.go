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

package proba

import (
	"container/heap"
	"context"
	"errors"
	"github.com/google/uuid"
	"math/rand"
	"openio-sds/tools/oio-rawx-harass/client"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// PopulationConfig gathers the core parameters of a swarm of probabilistic behaviors.
type PopulationConfig struct {

	// Concurrency management: at most MaxWorkers concurrent requests will
	// be allowed for EACH population run
	MaxWorkers int `yaml:"max_workers"`

	// Exit conditions: the stress is not meant to last forever, it's termination is time-based
	Duration time.Duration `yaml:"duration"
`
	// How long does the chunks live on the platform
	// Set long for a low deletion probability
	LifeExpectancy time.Duration `yaml:"life_expectancy"`
	LifeDeviation  time.Duration `yaml:"life_deviation"`

	// How many times is a chunk fetched, per second
	AverageGetFrequency float64 `yaml:"average_get_frequency"`

	// How often a chunk is created, per second
	AverageCreationFrequency float64 `yaml:"average_creation_frequency"`
}

// population of behaviors currently being run
type population struct {
	id string

	config    PopulationConfig
	nextIndex uint

	scenarios           ScenarioHeap
	requestedCreations  chan bool
	successfulCreations chan *Behavior
	failedCreations     chan *Behavior
}

const (
	batchSize = 32
)

type ScenarioGenerator func(clock time.Time) *Behavior

// Run implements the scenario.Runnable
// It spawns a completely new and independant population run. The Run function may be used multiple times.
func (cfg *PopulationConfig) Run(ctx context.Context, tgt client.RawxTarget, stats *client.Stats) error {
	if len(tgt.RawxUrl) <= 0 {
		return errors.New("No RAWX specified")
	}

	p := population{
		id:                  uuid.NewString(),
		config:              *cfg,
		nextIndex:           0,
		scenarios:           make(ScenarioHeap, 0),
		requestedCreations:  make(chan bool, 2),
		successfulCreations: make(chan *Behavior, cfg.MaxWorkers+1),
		failedCreations:     make(chan *Behavior, cfg.MaxWorkers+1),
	}

	index := uint(0)

	return p.run(ctx, &tgt, stats, func(clock time.Time) *Behavior {

		// TODO(jfs): determine a random lifetime, likely using a normal/gaussian random variable
		lifetime := time.Duration(rand.NormFloat64()*float64(cfg.LifeExpectancy)) + cfg.LifeDeviation
		death := clock.Add(lifetime)

		s := &Behavior{
			step:             stepIdle,
			deadlineGet:      clock,
			deadlineDeletion: death,
		}
		s.refcount.Store(0)
		s.Refresh(&tgt, index)
		index++

		return s
	})
}

// Patch overwrites the fields of the receiver whose corresponding field in the argument
// is set.
func (cfg *PopulationConfig) Patch(rhs PopulationConfig) {
	if rhs.Duration > 0 {
		cfg.Duration = rhs.Duration
	}
	if rhs.MaxWorkers > 0 {
		cfg.MaxWorkers = rhs.MaxWorkers
	}
	if rhs.LifeExpectancy > 0 {
		cfg.LifeExpectancy = rhs.LifeExpectancy
	}
	if rhs.LifeDeviation > 0 {
		cfg.LifeDeviation = rhs.LifeDeviation
	}
	if rhs.AverageGetFrequency > 0 {
		cfg.AverageGetFrequency = rhs.AverageGetFrequency
	}
	if rhs.AverageCreationFrequency > 0 {
		cfg.AverageCreationFrequency = rhs.AverageCreationFrequency
	}
}

func (pop *population) run(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats, generator ScenarioGenerator) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	pop.log(ctx).WithFields(log.Fields{
		"targets": tgt.RawxUrl,
		"put":     pop.config.AverageCreationFrequency,
		"get":     pop.config.AverageGetFrequency,
		"life":    pop.config.LifeExpectancy,
		"lifeDev": pop.config.LifeDeviation,
	}).Debug("stress starting")

	// Trigger chunk creations
	go func(ctx context.Context) {
		defer cancel()

		// TODO(jfs): Poisson would be better here
		interval := time.Duration(float64(time.Second) / pop.config.AverageCreationFrequency)
		ticker := time.NewTicker(interval)
		done := ctx.Done()

		pop.log(ctx).WithField("interval", interval).Debug("trigger starting")

	LOOP:
		for {
			select {
			case <-done:
				break LOOP
			case <-ticker.C:
				pop.requestedCreations <- true
			}
		}
		pop.log(ctx).Debug("trigger exiting")
	}(ctx)

	// Trigger the termination based on the configured duration
	go func(ctx context.Context) {
		defer cancel()

		pop.log(ctx).WithField("duration", pop.config.Duration).Debug("alarm starting")
		select {
		case <-ctx.Done():
			pop.log(ctx).Debug("alarm canceled")
			return
		case <-time.After(pop.config.Duration):
			pop.log(ctx).Debug("alarm triggered")
			return
		}
	}(ctx)

	// We bound the concurrency of the stress tool
	groupRun, ctx := errgroup.WithContext(ctx)
	groupRun.SetLimit(pop.config.MaxWorkers)
	lastProgress := time.Now()
	var totalPut, totalGet, totalDel uint

	printProgress := func(clock time.Time) {
		pop.log(ctx).WithFields(log.Fields{
			"_t":      clock,
			"started": totalPut,
			"fetched": totalGet,
			"deleted": totalDel,
		}).Info("progress")
	}

	for ctx.Err() == nil {
		clock := time.Now()
		pop.consumeCreationEvents(ctx, clock, generator)
		roundPut, roundGet, roundDel := pop.triggerOneBatch(ctx, tgt, stats, clock, groupRun)
		totalPut += roundPut
		totalGet += roundGet
		totalDel += roundDel

		if clock.Sub(lastProgress) > 5*time.Second {
			printProgress(clock)
			lastProgress = clock
		}

		time.Sleep(100 * time.Millisecond)
	}

	if e := groupRun.Wait(); e != nil {
		pop.log(ctx).WithError(e).Warn("worker error")
	}

	printProgress(time.Now())
	pop.teardown(ctx, tgt, stats, generator)

	pop.log(ctx).Debug("stress exiting")
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
			pop.log2(ctx, clock, s).WithField("status", "ok").Trace("created")
		case s := <-pop.failedCreations:
			pop.log2(ctx, clock, s).WithField("status", "error").Warn("creation failed")
		case <-pop.requestedCreations:
			s := generator(clock)
			pop.log2(ctx, clock, s).Trace("creation requested")
			pop.scenarios.Push(s)
		default:
			return
		}
	}
}

func (pop *population) triggerOneBatch(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats, clock time.Time, group *errgroup.Group) (uint, uint, uint) {
	var started, fetched, deleted uint
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
				s.Put(tgt, stats)
				pop.successfulCreations <- s
				return nil
			})
			if spawned {
				pop.log2(ctx, clock, s).Trace("create")
				started++
			} else {
				//s.deadlineGet.Add(20 * time.Millisecond)
				heap.Push(&pop.scenarios, s)
				break LOOP
			}

		case stepReady:
			if clock.After(s.deadlineDeletion) {
				spawned := group.TryGo(func() error {
					for s.refcount.Load() > 0 {
						time.Sleep(100 * time.Millisecond)
					}
					s.Del(tgt, stats)
					return nil
				})
				if spawned {
					deleted++
					pop.log2(ctx, clock, s).Trace("delete")
				} else {
					heap.Push(&pop.scenarios, s)
					break LOOP
				}
			} else {
				group.Go(func() error {
					s.refcount.Add(1)
					defer s.refcount.Add(^uint32(0))
					s.Get(tgt, stats)
					return nil
				})
				pop.log2(ctx, clock, s).Trace("fetch")
				fetched++
				pop.refreshDeadline(clock, s)
				heap.Push(&pop.scenarios, s)
			}
		}
	}

	return started, fetched, deleted
}

func (pop *population) teardown(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats, generator ScenarioGenerator) {
	pop.log(ctx).Debug("teardown starting")

	groupTail, ctx := errgroup.WithContext(ctx)
	groupTail.SetLimit(pop.config.MaxWorkers)

	for pop.scenarios.Len() > 0 {
		clock := time.Now()

		pop.consumeCreationEvents(ctx, clock, generator)

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
			s.Del(tgt, stats)
			return nil
		})
		pop.log2(ctx, clock, s).Trace("delete")
	}

	pop.log(ctx).Debug("teardown exiting")
}

func (pop *population) refreshDeadline(clock time.Time, s *Behavior) {
	// TODO(jfs): also, the application of the Poisson law would make sense here
	interval := time.Duration(float64(time.Second) / pop.config.AverageGetFrequency)
	s.deadlineGet = clock.Add(interval)
}

// Generate a log event for the current population run
func (pop *population) log(ctx context.Context) *log.Entry {
	return log.WithField("_p", pop.id).WithContext(ctx)
}

// Generate a log event for the given Behavior
func (pop *population) log2(ctx context.Context, clock time.Time, s *Behavior) *log.Entry {
	return pop.log(ctx).WithField("_id", s.GetIndex()).WithField("_t", clock)
}
