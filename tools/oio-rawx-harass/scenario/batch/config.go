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
	"errors"
	"time"

	"github.com/google/uuid"
	"openio-sds/tools/oio-rawx-harass/config"
	"openio-sds/tools/oio-rawx-harass/distribution"
	"openio-sds/tools/oio-rawx-harass/scenario"
)

type PoissonLoad struct {
	// The number of RAWX services the current load is based on.
	// The actual load will be based on a ratio of the configuration here-below applied
	// to the actual number of targets.
	Services int `yaml:"services"`

	// Lambda of the variable (Poisson law) triggering PUT on the interval of 1s.
	LambdaPut int `yaml:"put"`

	// Lambda of the variable (Poisson law) triggering GET on the interval of 1s, for 1G chunks
	LambdaGet int `yaml:"get"`

	// Lambda of the variable (Poisson law) triggering DELETE on the interval of 1s, for 1G chunks
	LambdaDel int `yaml:"del"`

	// Set to 0 for an unbound duration
	Duration time.Duration `yaml:"duration"`
}

// Config gathers the core parameters of a swarm of probabilistic behaviors.
type Config struct {
	// For pretty-printing purposes
	Name string `yaml:"name"`

	// Concurrency management: at most MaxWorkers concurrent requests will
	// be allowed for EACH population run
	MaxWorkers int `yaml:"max_workers"`

	// Set to true to discover the existing chunks as already warmed up entities
	// Very dangerous option that can trigger the deletion of those chunks during the CleanUp phase.
	Discover bool `yaml:"discover"`

	// Set to true to delete the chunks of the population of the current test at the CleanUp phase of the test
	Cleanup bool `yaml:"cleanup"`

	// How many chunks will be pre-created during the WarmUp phase
	WarmupChunks int64 `yaml:"warmup"`

	Loads []PoissonLoad `yaml:"load"`

	// Name of the sizes profile
	Sizes string `yaml:"sizes"`

	// Number
	DeletesPerTarget uint32 `yaml:"deletes_per_target"`
}

func NewConfig() *Config {
	return &Config{
		Name:         uuid.NewString(),
		MaxWorkers:   8,
		WarmupChunks: 0,
		Discover:     false,
		Cleanup:      true,
		Loads:        make([]PoissonLoad, 0),
		Sizes:        "default",

		DeletesPerTarget: 16384,
	}
}

type ScenarioGenerator func(clock time.Time) *Behavior

// Run implements the scenario.Runnable
// It spawns a completely new and independant population run. The Run function may be used multiple times.
func (cfg *Config) Build(ctx context.Context, sz *config.SizesConfiguration, tgt *config.RawxTargets) (scenario.Runnable, error) {
	localSizes := (*sz)[cfg.Sizes]
	if len(localSizes) <= 0 {
		return nil, errors.New("no size histogram specified")
	}

	p := &population{
		AbstractPopulation: scenario.AbstractPopulation{
			Id: cfg.Name,
		},

		config:           *cfg,
		accumulatedSizes: distribution.NewSizeHistograms(localSizes),
		targets:          tgt,

		scenarios:    make([]*targetPopulation, 0),
		requestedPut: make(chan bool, 2),
		requestedGet: make(chan bool, 2),
		requestedDel: make(chan bool, 2),
		created:      make(chan opResult, cfg.MaxWorkers*2),
		deleted:      make(chan opResult, cfg.MaxWorkers*2),
		getted:       make(chan opResult, cfg.MaxWorkers*2),

		loads: make([]*loadProfile, 0),
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

	for _, lCfg := range cfg.Loads {
		// The provided lambda is meaningful for a given number of services.
		// But we likely deal with another number of services. Let's ratio the lambda
		// accordingly.
		ratio := func(y int) int { return (y * tgt.Count()) / lCfg.Services }

		l := &loadProfile{
			duration:   lCfg.Duration,
			poissonGet: distribution.NewPoissonSlots(ratio(lCfg.LambdaGet)),
			poissonDel: distribution.NewPoissonSlots(ratio(lCfg.LambdaDel)),
			poissonPut: distribution.NewPoissonSlots(ratio(lCfg.LambdaPut)),
		}
		p.loads = append(p.loads, l)
	}

	for _, t := range tgt.Targets {
		p.scenarios = append(p.scenarios, &targetPopulation{
			scenarios: make([]*Behavior, 0),
			quotaDel:  cfg.DeletesPerTarget,
			rawx:      t.URL(),
		})
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
	if rhs.WarmupChunks > 0 {
		cfg.WarmupChunks = rhs.WarmupChunks
	}

	cfg.Discover = rhs.Discover
	cfg.Cleanup = rhs.Cleanup
	cfg.DeletesPerTarget = rhs.DeletesPerTarget

	if len(rhs.Loads) > 0 {
		cfg.Loads = append(cfg.Loads, rhs.Loads...)
	}
	if rhs.Sizes != "" {
		cfg.Sizes = rhs.Sizes
	}
}
