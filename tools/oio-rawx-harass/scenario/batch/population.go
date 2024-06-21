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
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"openio-sds/tools/oio-rawx-harass/client"
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

// population of behaviors currently being run
type population struct {
	scenario.AbstractPopulation

	config Config

	scenarios []*Behavior
	size      int32

	requestedPut chan bool
	requestedDel chan bool
	requestedGet chan bool

	successfulCreations chan *Behavior
	failedCreations     chan *Behavior

	generator ScenarioGenerator

	// Weight is the cumulated weight for that size slot
	accumulatedSizes utils.SizeHistograms

	// cumulated probabilities of
	poissonGet utils.PoissonDistribution
	poissonDel utils.PoissonDistribution
	poissonPut utils.PoissonDistribution
}

func (pop *population) discover(ctx context.Context, url string) error {
	pop.Log(ctx).WithField("rawx", url).Debug("discovery starting")

	count := uint64(0)
	urlTokens := strings.Split(url, ":")
	ip, port := urlTokens[0], urlTokens[1]

	// the discovery os achieved by a local agent on the same IP by a well-known port
	resp, err := http.Get(fmt.Sprintf("http://%s:%d/%d", ip, utils.DiscoveryPort, port))
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		return fmt.Errorf("http error: %w", err)
	} else if resp.StatusCode/100 != 2 {
		return fmt.Errorf("http error: unexpected code %v", resp.StatusCode)
	} else {
		lines := bufio.NewScanner(resp.Body)
		lines.Split(bufio.ScanLines)
		for lines.Scan() {
			line := lines.Text()
			line = strings.TrimSpace(line)
			tokens := strings.SplitN(line, " ", 3)
			chunkId, _ := tokens[0], tokens[1]

			s := pop.generator(time.Now())
			s.Craft(s.globalIndex, url, chunkId)
		}
	}

	pop.Log(ctx).WithField("rawx", url).WithField("count", count).Debug("discovery exiting")
	return nil
}

func (pop *population) Warmup(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error {
	pop.Log(ctx).WithFields(log.Fields{
		"targets": tgt.RawxUrl,
		"count":   pop.config.WarmupChunks,
	}).Debug("warmup starting")

	groupWarmup, ctx := errgroup.WithContext(ctx)
	if pop.config.MaxWorkers > 0 {
		groupWarmup.SetLimit(pop.config.MaxWorkers)
	} else {
		groupWarmup.SetLimit(4)
	}

	progress := utils.NewProgress(time.Now(), pop.Id)

	if pop.config.Discover {
		for _, t := range tgt.RawxUrl {
			if err := pop.discover(ctx, t); err != nil {
				return fmt.Errorf("discovery failed on target %s: %w", t, err)
			}
		}
	}

	// Creation of chunks
	for i := int64(0); i < pop.config.WarmupChunks; i++ {
		clock := time.Now()
		s := pop.generator(clock)
		s.Refresh(tgt, s.globalIndex)
		groupWarmup.Go(func() error {
			err, _, _ := s.Put(stats, s.size)
			if err != nil {
				pop.log2(ctx, clock, s).WithFields(s.LogFields()).WithError(err).Info("PUT failed")
			} else {
				atomic.AddUint64(&progress.TotalPut, 1)
			}
			return nil
		})
		pop.scenarios = append(pop.scenarios, s)

		progress.PrintPeriodically(ctx, clock)
	}

	err := groupWarmup.Wait()

	progress.Print(ctx, time.Now())

	pop.Log(ctx).WithFields(log.Fields{
		"targets": tgt.RawxUrl,
		"count":   pop.config.WarmupChunks,
	}).WithError(err).Debug("warmup exiting")
	return err
}

func (pop *population) Run(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error {
	if pop.config.MaxWorkers <= 0 {
		pop.config.MaxWorkers = 32
	}

	pop.Log(ctx).WithFields(log.Fields{
		"targets": tgt.RawxUrl,
		"put":     pop.config.LambdaPut,
		"get":     pop.config.LambdaGet,
		"del":     pop.config.LambdaDel,
	}).Debug("stress starting")

	// We bound the concurrency of the stress tool
	groupRun, ctx := errgroup.WithContext(ctx)
	groupRun.SetLimit(pop.config.MaxWorkers + 3)

	groupRun.Go(func() error {
		utils.AperiodicTicker(ctx, pop.requestedPut, func() int {
			return pop.poissonPut.Poll()
		})
		return nil
	})
	groupRun.Go(func() error {
		utils.AperiodicTicker(ctx, pop.requestedGet, func() int {
			return pop.poissonGet.PollAtScale(int(atomic.LoadInt32(&pop.size)), 1000000)
		})
		return nil
	})
	groupRun.Go(func() error {
		utils.AperiodicTicker(ctx, pop.requestedDel, func() int {
			return pop.poissonDel.PollAtScale(int(atomic.LoadInt32(&pop.size)), 1000000)
		})
		return nil
	})

	progress := utils.NewProgress(time.Now(), pop.Id)

LOOP:
	for ctx.Err() == nil {
		clock := time.Now()

		select {
		case <-ctx.Done():
			break LOOP

		case s := <-pop.successfulCreations:
			pop.scenarios = append(pop.scenarios, s)
			pop.log2(ctx, clock, s).WithField("status", "ok").Trace("created")
		case s := <-pop.failedCreations:
			pop.log2(ctx, clock, s).WithField("status", "error").Warn("creation failed")

		case _, ok := <-pop.requestedPut:
			if !ok {
				break LOOP
			}
			s := pop.generator(clock)
			s.Refresh(tgt, s.globalIndex)
			pop.log2(ctx, clock, s).Trace("creation requested")

		case _, ok := <-pop.requestedGet:
			if !ok {
				break LOOP
			}
			if s := pop.choose(); s != nil {
				spawned := groupRun.TryGo(func() error {
					s.refcount.Add(1)
					defer s.refcount.Add(^uint32(0))
					s.Get(stats)
					return nil
				})
				if spawned {
					pop.log2(ctx, clock, s).Trace("fetch")
					progress.TotalGet++
				}
			}

		case _, ok := <-pop.requestedDel:
			if !ok {
				break LOOP
			}
			if s := pop.steal(); s != nil {
				spawned := groupRun.TryGo(func() error {
					for s.refcount.Load() > 0 {
						time.Sleep(100 * time.Millisecond)
					}
					s.Del(stats)
					return nil
				})
				if spawned {
					progress.TotalDel++
					pop.log2(ctx, clock, s).Trace("delete")
				} else {
					pop.scenarios = append(pop.scenarios, s)
				}
			}
		}

		atomic.StoreInt32(&pop.size, int32(len(pop.scenarios)))

		progress.PrintPeriodically(ctx, clock)
	}

	pop.Log(ctx).Debug("stress tearing down")

	if e := groupRun.Wait(); e != nil {
		pop.Log(ctx).WithError(e).Warn("worker error")
	}

	pop.Log(ctx).Debug("stress workers exited")

	// the 3 trigger channels have been close by their generator function
	close(pop.successfulCreations)
	close(pop.failedCreations)
	for s := range pop.successfulCreations {
		pop.scenarios = append(pop.scenarios, s)
		pop.log2(ctx, time.Now(), s).WithField("status", "ok").Trace("created")
	}
	for s := range pop.failedCreations {
		pop.log2(ctx, time.Now(), s).WithField("status", "error").Warn("creation failed")
	}

	progress.Print(ctx, time.Now())

	pop.Log(ctx).Debug("stress exiting")
	return nil
}

// get a pointer to a random element
func (pop *population) choose() *Behavior {
	l := len(pop.scenarios)
	if l <= 0 {
		return nil
	}
	idx := rand.Intn(l)
	return pop.scenarios[idx]
}

// choose and remove the chosen
func (pop *population) steal() *Behavior {
	l := len(pop.scenarios)
	if l <= 0 {
		return nil
	}

	idx := rand.Intn(l)
	b := pop.scenarios[idx]
	pop.scenarios[idx] = pop.scenarios[l-1] // fast remove
	pop.scenarios = pop.scenarios[:l-1]
	return b
}

func (pop *population) Cleanup(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error {
	if !pop.config.Cleanup {
		pop.Log(ctx).Debug("cleanup skipped")
		return nil
	}

	pop.Log(ctx).Debug("cleanup starting")

	groupTail, ctx := errgroup.WithContext(ctx)
	groupTail.SetLimit(pop.config.MaxWorkers)

	for len(pop.scenarios) > 0 {
		clock := time.Now()

		s := pop.steal()

		groupTail.Go(func() error {
			for s.refcount.Load() > 0 {
				// This should never happen since all the GET workers are now shut down
				time.Sleep(100 * time.Millisecond)
			}
			s.Del(stats)
			return nil
		})
		pop.log2(ctx, clock, s).Trace("delete")
	}

	pop.Log(ctx).Debug("cleanup exiting")
	return nil
}

// Generate a log event for the given Behavior
func (pop *population) log2(ctx context.Context, clock time.Time, s *Behavior) *log.Entry {
	return pop.Log(ctx).WithField("_id", s.globalIndex).WithField("_t", clock)
}
