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
	"errors"
	"openio-sds/tools/oio-rawx-harass/scenario"

	log "github.com/sirupsen/logrus"
	"openio-sds/tools/oio-rawx-harass/client"
)

type ScenarioGenerator func() Behavior

type population struct {
	scenario.AbstractPopulation

	cfg Config

	// Behavioral feature flags
	nextStepAfterPUT stepAction
	nextStepAfterGET stepAction
	nextStepAfterDEL stepAction

	scenarios []Behavior
	generator ScenarioGenerator
}

// Implements scenario.Runnable
func (pop *population) Run(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error {
	if tgt.Empty() {
		return errors.New("Missing target")
	}
	if stats == nil {
		return errors.New("Missing stats")
	}

	log.WithFields(log.Fields{
		"targets":  tgt.RawxUrl,
		"afterPut": toString(pop.nextStepAfterPUT),
		"afterGet": toString(pop.nextStepAfterGET),
		"afterDel": toString(pop.nextStepAfterDEL),
	}).Debug("stress starting")

	pending := make(chan *Behavior, 8)
	done := make(chan *Behavior, 64)
	exited := make(chan bool)
	waiting := list.New()
	runningWorkers := 0

	// Prepare the scenarios
	for i := uint(0); i < pop.cfg.NbScenarios; i++ {
		pop.scenarios = append(pop.scenarios, pop.generator())
	}
	for i, _ := range pop.scenarios {
		s := &pop.scenarios[i]
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
	for i := uint(0); i < pop.cfg.NbWorkers; i++ {
		runningWorkers += 1
		go worker()
	}

	// Fire scenarios until a termination event occurs
	log.WithFields(log.Fields{
		"scenarios": len(pop.scenarios),
		"workers":   pop.cfg.NbWorkers,
	}).Info("stress running")

	func() {
		// Using a function let us `return` from it much more easily than
		// breaking a `for` loop from a `select` statement
		for ctx.Err() != nil {
			if e := waiting.Front(); e != nil {
				select {
				case s := <-done:
					waiting.PushBack(s)
				case pending <- e.Value.(*Behavior):
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
	}).Info("shutting down")

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
		"targets":  tgt.RawxUrl,
		"afterPut": toString(pop.nextStepAfterPUT),
		"afterGet": toString(pop.nextStepAfterGET),
		"afterDel": toString(pop.nextStepAfterDEL),
	}).Debug("stress exiting")
	return nil
}

func (pop *population) Cleanup(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error {
	if tgt.Empty() {
		return errors.New("Missing target")
	}
	if stats == nil {
		return errors.New("Missing stats")
	}

	log.WithContext(ctx).Debug("cleanup starting")

	for _, s := range pop.scenarios {
		s.TearDown(tgt, stats)
	}

	log.WithContext(ctx).WithField("targets", tgt.RawxUrl).Debug("cleanup exiting")
	return nil
}
