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
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gopkg.in/yaml.v3"
	"io"
	"openio-sds/tools/oio-rawx-harass/client"
	"openio-sds/tools/oio-rawx-harass/scenario"
	"openio-sds/tools/oio-rawx-harass/scenario/proba"
	"os"
)

type Batch struct {
	Hosts client.RawxTarget
	Pops  []scenario.Runnable
}

type ProbabilisticConfig struct {
	proba.PopulationConfig
	Class string `yaml:"class"`
}

type LegacyConfig struct {
	Args proba.PopulationConfig `yaml:"args"`
}

type BatchConfig struct {
	Targets []string              `yaml:"targets"`
	Proba   []ProbabilisticConfig `yaml:"probabilistic"`
	Legacy  []LegacyConfig        `yaml:"legacy"`
}

func makeProbabilistic(class string) (error, *proba.PopulationConfig) {
	switch class {
	case "standard":
		return nil, proba.NewPopulationStandard()
	case "ia":
		return nil, proba.NewPopulationIA()
	case "glacier", "glacier-ir":
		return nil, proba.NewPopulationGlacier()
	default:
		return fmt.Errorf("Invalid class selector %s", class), nil
	}
}

func (b *Batch) LoadReader(in io.Reader) error {
	batchCfg := BatchConfig{}
	decoder := yaml.NewDecoder(in)
	if err := decoder.Decode(&batchCfg); err != nil {
		return err
	}

	if len(batchCfg.Targets) == 0 {
		return errors.New("no target specified")
	}
	b.Hosts.RawxUrl = batchCfg.Targets

	for _, cfg := range batchCfg.Proba {
		err, pop := makeProbabilistic(cfg.Class)
		if err != nil {
			return err
		}
		pop.Patch(cfg.PopulationConfig)

		log.WithField("args", *pop).WithField("class", cfg.Class).Debug("batch item configured")
		b.Pops = append(b.Pops, pop)
	}
	return nil
}

func (b *Batch) LoadPath(path string) error {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return fmt.Errorf("Batch file error: %w", err)
	}

	return b.LoadReader(f)
}

// Run implements scenario.Runnable.Run
func (b *Batch) Run(ctx context.Context, tgt client.RawxTarget, stats *client.Stats) error {
	if len(tgt.RawxUrl) <= 0 {
		return errors.New("No RAWX specified")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)

	for _, pop := range b.Pops {
		g.Go(func() error {
			err, st := scenario.Run(ctx, tgt, pop)
			stats.Add(st)
			return err
		})
	}
	err := g.Wait()
	return err
}
