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
	"context"
	"errors"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"openio-sds/tools/oio-rawx-harass/config"
	"openio-sds/tools/oio-rawx-harass/distribution"
	"openio-sds/tools/oio-rawx-harass/scenario"
	"openio-sds/tools/oio-rawx-harass/utils"
)

// Config gathers the core parameters of a swarm of probabilistic behaviors.
type Config struct {
	// For pretty-printing purposes
	Name string `yaml:"name"`

	// Concurrency management: at most MaxWorkers concurrent requests will
	// be allowed for EACH population run
	MaxWorkers int `yaml:"max_workers"`

	// How many chunks will be pre-created during the WarmUp phase
	WarmupChunks int64 `yaml:"warmup"`

	// Set to true to delete the chunks of the population of the current test at the CleanUp phase of the test
	Cleanup bool `yaml:"cleanup"`

	// How long does the chunks live on the platform
	// Set long for a low deletion probability
	LifeExpectancy time.Duration `yaml:"life_expectancy"`
	LifeDeviation  time.Duration `yaml:"life_deviation"`

	// How many times is a chunk fetched, per second
	AverageGetFrequency float64 `yaml:"average_get_frequency"`

	// How often a chunk is created, per second
	AverageCreationFrequency float64 `yaml:"average_creation_frequency"`

	// NAme of the size profile to be used for new chunks
	Sizes string `yaml:"sizes"`
}

func NewConfig() *Config {
	return &Config{
		Name:                     uuid.NewString(),
		MaxWorkers:               8,
		WarmupChunks:             0,
		Cleanup:                  true,
		AverageGetFrequency:      0.1,
		AverageCreationFrequency: 1,
		LifeExpectancy:           30 * time.Second,
		LifeDeviation:            5 * time.Second,
		Sizes:                    "",
	}
}

type ScenarioGenerator func(clock time.Time) *Behavior

// Patch overwrites the fields of the receiver whose corresponding field in the argument
// is set.
func (cfg *Config) Patch(rhs Config) {
	if rhs.Name != "" {
		cfg.Name = rhs.Name
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
	if rhs.WarmupChunks > 0 {
		cfg.WarmupChunks = rhs.WarmupChunks
	}
	if rhs.Sizes != "" {
		cfg.Sizes = rhs.Sizes
	}
}

// Run implements the scenario.Runnable
// It spawns a completely new and independant population run. The Run function may be used multiple times.
func (cfg *Config) Build(ctx context.Context, sizes *config.SizesConfiguration, tgt *config.RawxTargets) (scenario.Runnable, error) {
	localSizes := (*sizes)[cfg.Sizes]
	if len(localSizes) <= 0 {
		return nil, errors.New("no size histogram specified")
	}

	p := &population{
		AbstractPopulation: scenario.AbstractPopulation{
			Id: cfg.Name,
		},
		config:           *cfg,
		targets:          tgt,
		accumulatedSizes: distribution.NewSizeHistograms(localSizes),

		scenarios:           make(utils.ScenarioHeap, 0),
		requestedCreations:  make(chan bool, 2),
		successfulCreations: make(chan *Behavior, cfg.MaxWorkers+1),
		failedCreations:     make(chan *Behavior, cfg.MaxWorkers+1),
	}

	index := uint(0)

	p.generator = func(clock time.Time) *Behavior {

		// TODO(jfs): determine a random lifetime, likely using a normal/gaussian random variable
		lifetime := time.Duration(rand.NormFloat64()*float64(cfg.LifeExpectancy)) + cfg.LifeDeviation
		death := clock.Add(lifetime)

		s := &Behavior{
			step:             stepIdle,
			heapIndex:        -1,
			globalIndex:      index,
			deadlineGet:      clock,
			deadlineDeletion: death,
			size:             p.accumulatedSizes.Poll(),
		}
		s.refcount.Store(0)
		index++

		return s
	}
	return p, nil
}
