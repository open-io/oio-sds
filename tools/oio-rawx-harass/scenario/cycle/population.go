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
	"container/list"
	"context"
	log "github.com/sirupsen/logrus"
	"openio-sds/tools/oio-rawx-harass/client"
)

type Scenario interface {
	SetUp(index uint)
	TearDown()

	// Triggers the next step of the
	Step(tgt *client.RawxTarget, st *client.Stats)
}

type ScenarioGenerator func() Scenario

type population struct {
	cfg PopulationConfig

	// Behavioral feature flags
	nextStepAfterPUT stepAction
	nextStepAfterGET stepAction
	nextStepAfterDEL stepAction
}

func (pl *population) Run(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats, generator ScenarioGenerator) error {

	ctx, cancel := context.WithTimeout(ctx, pl.cfg.Duration)
	defer cancel()

	scenarios := make([]Scenario, 0)
	pending := make(chan Scenario, 8)
	done := make(chan Scenario, 64)
	exited := make(chan bool)
	waiting := list.New()
	runningWorkers := 0

	// Prepare the scenarios
	for i := uint(0); i < pl.cfg.NbScenarios; i++ {
		scenarios = append(scenarios, generator())
	}
	for i, s := range scenarios {
		s.SetUp(uint(i))
		waiting.PushBack(s)
	}

	// Prepare the workers
	worker := func() {
		for s := range pending {
			s.Step(tgt, stats)
			done <- s
		}
		exited <- true
	}
	for i := uint(0); i < pl.cfg.NbWorkers; i++ {
		runningWorkers += 1
		go worker()
	}

	// Fire scenarios until a termination event occurs
	log.WithFields(log.Fields{
		"scenarios": len(scenarios),
		"workers":   pl.cfg.NbWorkers,
	}).Info("running")

	func() {
		// Using a function let us `return` from it much more easily than
		// breaking a `for` loop from a `select` statement
		for ctx.Err() != nil {
			if e := waiting.Front(); e != nil {
				select {
				case s := <-done:
					waiting.PushBack(s)
				case pending <- e.Value.(Scenario):
					waiting.Remove(e)
					e = nil
				case <-ctx.Done():
					return
				}
			} else {
				// This happens when we have more workers than scenarios
				select {
				case s := <-done:
					waiting.PushBack(s)
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Termination sequence
	log.WithFields(log.Fields{
		"pending": len(pending),
		"workers": runningWorkers,
	}).Info("Shutting down")

	close(pending)
	for runningWorkers > 0 {
		select {
		case <-exited:
			runningWorkers--
		case s := <-done:
			waiting.PushBack(s)
		}
	}

	waiting.Init()

	log.WithFields(log.Fields{
		"scenarios": len(scenarios),
	}).Info("Tearing down")

	for _, s := range scenarios {
		s.TearDown()
	}

	return nil
}
