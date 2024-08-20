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

package ensemble

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
	"openio-sds/tools/oio-rawx-harass/config"
	"openio-sds/tools/oio-rawx-harass/scenario"
	"openio-sds/tools/oio-rawx-harass/scenario/batch"
	"openio-sds/tools/oio-rawx-harass/scenario/cycle"
	"openio-sds/tools/oio-rawx-harass/scenario/flock"
	"openio-sds/tools/oio-rawx-harass/utils"
)

type BatchConfig struct {
	Args batch.Config `yaml:"args"`
}

type FlockConfig struct {
	Args flock.Config `yaml:"args"`
}

type CyclesConfig struct {
	Args cycle.Config `yaml:"args"`
}

type Config struct {
	Name string `yaml:"name"`

	// 2 fields loaded straight from the config. Beware, the risk of blank fields is very high
	Batches []BatchConfig  `yaml:"batch"`
	Flocks  []FlockConfig  `yaml:"flock"`
	Legacy  []CyclesConfig `yaml:"cycle"`

	builders []scenario.RunnableBuilder
}

func NewConfig() Config {
	return Config{
		Name: uuid.NewString(),
	}
}

func NamedConfig(name string) Config {
	cfg := NewConfig()
	cfg.Name = name
	return cfg
}

func (cfg *Config) LoadReader(in io.Reader) error {
	decoder := yaml.NewDecoder(in)
	if err := decoder.Decode(cfg); err != nil {
		return err
	}

	for _, popCfg := range cfg.Legacy {
		pop := &cycle.Config{}
		*pop = popCfg.Args
		cfg.builders = append(cfg.builders, pop)
	}
	for _, popCfg := range cfg.Flocks {
		pop := flock.NewConfig() // ensure default values
		pop.Patch(popCfg.Args)   // override with explicit values
		cfg.builders = append(cfg.builders, pop)
	}
	for _, popCfg := range cfg.Batches {
		pop := batch.NewConfig()
		pop.Patch(popCfg.Args)
		cfg.builders = append(cfg.builders, pop)
	}

	if len(cfg.builders) == 0 {
		return errors.New("no scenario specified")
	}

	return nil
}

func (cfg *Config) LoadPath(ctx context.Context, path string) error {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return fmt.Errorf("open error with path '%s': %w", path, err)
	}

	if err = cfg.LoadReader(f); err != nil {
		return err
	} else {
		utils.Log(ctx).WithField("path", path).WithField("count", len(cfg.builders)).Debug("configuration loaded")
		return nil
	}
}

func (cfg *Config) Merge(rhs *Config) {
	cfg.builders = append(cfg.builders, rhs)
}

// Count returns the number of actual population builders making the ensemble.
func (cfg *Config) Count() int {
	return len(cfg.builders)
}

func (cfg *Config) Build(ctx context.Context, sizes *config.SizesConfiguration, tgt *config.RawxTargets) (scenario.Runnable, error) {
	if len(cfg.builders) == 0 {
		return nil, errors.New("no scenario specified")
	}
	if tgt.Empty() {
		return nil, errors.New("no target specified")
	}
	if len(*sizes) == 0 {
		return nil, errors.New("no size specified")
	}

	b := &Population{
		AbstractPopulation: scenario.AbstractPopulation{
			Id: cfg.Name,
		},
		pops: make([]scenario.Runnable, 0),
	}

	for _, popCfg := range cfg.builders {
		if pop, err := popCfg.Build(ctx, sizes, tgt); err != nil {
			utils.Log(ctx).WithError(err).Warn("build error %+v ", popCfg)
			return nil, err
		} else {
			utils.Log(ctx).Debugf("population created %+v", popCfg)
			b.pops = append(b.pops, pop)
		}
	}

	utils.Log(ctx).WithField("populations", len(b.pops)).WithField("targets", tgt.Count()).Debug("build done")
	return b, nil
}
