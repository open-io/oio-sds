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

package push

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"openio-sds/tools/oio-rawx-harass/client"
	"openio-sds/tools/oio-rawx-harass/scenario"
	"openio-sds/tools/oio-rawx-harass/utils"
)

// Config gathers the core parameters of a swarm of probabilistic behaviors.
type Config struct {
	// Concurrency management: at most MaxWorkers concurrent requests will
	// be allowed for EACH population run
	MaxWorkers int `yaml:"max_workers"`

	Targets []string `yaml:"targets"`

	// Weight is the absolute weight for that size slot
	Sizes []utils.SizeSlot `yaml:"sizes"`
}

func NewConfig() *Config {
	return &Config{
		MaxWorkers: 32,
		Targets:    []string{},
		Sizes: []utils.SizeSlot{
			utils.SizeSlot{8 * 1024 * 1024, 1},
		},
	}
}

// Not made to be standalone
func (cfg *Config) GetTargets() client.RawxTarget {
	return client.MakeTargets(cfg.Targets)
}

// Run implements the scenario.Runnable
// It spawns a completely new and independant population run. The Run function may be used multiple times.
func (cfg *Config) Build() (scenario.Runnable, error) {
	if len(cfg.Sizes) <= 0 {
		return nil, errors.New("no size histogram specified")
	}

	p := &population{
		AbstractPopulation: scenario.AbstractPopulation{
			Id: uuid.NewString(),
		},
		config:           *cfg,
		accumulatedSizes: utils.NewSizeHistograms(cfg.Sizes),
	}

	return p, nil
}

func (bc *Config) LoadReader(in io.Reader) error {
	decoder := yaml.NewDecoder(in)
	if err := decoder.Decode(bc); err != nil {
		return err
	}
	return nil
}

func (bc *Config) LoadPath(path string) error {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return fmt.Errorf("batch file error: %w", err)
	}

	return bc.LoadReader(f)
}
