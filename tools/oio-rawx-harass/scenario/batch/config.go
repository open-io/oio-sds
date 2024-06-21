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
	"errors"
	"time"

	"github.com/google/uuid"
	"openio-sds/tools/oio-rawx-harass/client"
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

	// Set to true to discover the existing chunks as already warmed up entities
	// Very dangerous option that can trigger the deletion of thoose chunks during the CleanUp phase.
	Discover bool `yaml:"discover"`

	// How many chunks will be pre-created during the WarmUp phase
	WarmupChunks int64 `yaml:"warmup"`

	// Set to true to delete the chunks of the population of the current test at the CleanUp phase of the test
	Cleanup bool `yaml:"cleanup"`

	// Lambda of the variable (Poisson law) triggering PUT on the interval of 1s.
	// e.
	LambdaPut int `yaml:"lambda_put"`

	// Lambda of the variable (Poisson law) triggering GET on the interval of 1s, for 1M chunks
	LambdaGet int `yaml:"lambda_get"`

	// Lambda of the variable (Poisson law) triggering DELETE on the interval of 1s, for 1M chunks
	LambdaDel int `yaml:"lambda_del"`

	// Weight is the absolute weight for that size slot
	Sizes []utils.SizeSlot `yaml:"sizes"`
}

func NewConfig() *Config {
	return &Config{
		Name:         uuid.NewString(),
		MaxWorkers:   8,
		WarmupChunks: 0,
		Discover:     false,
		Cleanup:      true,
		LambdaPut:    130,
		LambdaGet:    20,
		LambdaDel:    2,
	}
}

type ScenarioGenerator func(clock time.Time) *Behavior

// Not made to be standalone
func (cfg *Config) GetTargets() client.RawxTarget { return client.NoTarget() }

// Run implements the scenario.Runnable
// It spawns a completely new and independant population run. The Run function may be used multiple times.
func (cfg *Config) Build() (scenario.Runnable, error) {
	if len(cfg.Sizes) <= 0 {
		return nil, errors.New("no size histogram specified")
	}

	p := &population{
		AbstractPopulation: scenario.AbstractPopulation{
			Id: cfg.Name,
		},
		config:              *cfg,
		scenarios:           make([]*Behavior, 0),
		requestedPut:        make(chan bool, 2),
		requestedGet:        make(chan bool, 2),
		requestedDel:        make(chan bool, 2),
		successfulCreations: make(chan *Behavior, cfg.MaxWorkers+1),
		failedCreations:     make(chan *Behavior, cfg.MaxWorkers+1),

		accumulatedSizes: utils.NewSizeHistograms(cfg.Sizes),

		poissonGet: utils.NewPoissonSlots(cfg.LambdaGet),
		poissonDel: utils.NewPoissonSlots(cfg.LambdaDel),
		poissonPut: utils.NewPoissonSlots(cfg.LambdaPut),
	}

	index := uint(0)

	p.generator = func(clock time.Time) *Behavior {
		s := &Behavior{
			globalIndex: index,
			size:        p.accumulatedSizes.Poll(),
		}
		s.refcount.Store(0)
		index++
		return s
	}

	return p, nil
}

// Patch overwrites the fields of the receiver whose corresponding field in the argument
// is set.
func (cfg *Config) Patch(rhs Config) {
	if rhs.Name != "" {
		cfg.Name = rhs.Name
	}
	if rhs.MaxWorkers > 0 {
		cfg.MaxWorkers = rhs.MaxWorkers
	}
	if rhs.LambdaGet > 0 {
		cfg.LambdaGet = rhs.LambdaGet
	}
	if rhs.LambdaPut > 0 {
		cfg.LambdaPut = rhs.LambdaPut
	}
	if rhs.WarmupChunks > 0 {
		cfg.WarmupChunks = rhs.WarmupChunks
	}

	cfg.Sizes = make([]utils.SizeSlot, len(rhs.Sizes))
	copy(cfg.Sizes, rhs.Sizes)
}
