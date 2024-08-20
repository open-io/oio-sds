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
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"openio-sds/tools/oio-rawx-harass/config"
	"openio-sds/tools/oio-rawx-harass/distribution"
	"openio-sds/tools/oio-rawx-harass/scenario"
)

// Config gathers the core parameters of a swarm of probabilistic behaviors.
type Config struct {
	// Concurrency management: at most MaxWorkers concurrent requests will
	// be allowed for EACH population run
	MaxWorkers int `yaml:"max_workers"`

	// Name of the size profile to be used
	Sizes string `yaml:"sizes"`
}

func NewConfig() *Config {
	return &Config{
		MaxWorkers: 32,
		Sizes:      "default",
	}
}

// Run implements the scenario.Runnable
// It spawns a completely new and independant population run. The Run function may be used multiple times.
func (cfg *Config) Build(ctx context.Context, sz *config.SizesConfiguration, tgt *config.RawxTargets) (scenario.Runnable, error) {
	localSizes := (*sz)[cfg.Sizes]
	if len(localSizes) <= 0 {
		return nil, errors.New("no local size histogram specified")
	}

	p := &population{
		AbstractPopulation: scenario.AbstractPopulation{
			Id: uuid.NewString(),
		},
		config:           *cfg,
		targets:          tgt,
		accumulatedSizes: distribution.NewSizeHistograms(localSizes),
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
