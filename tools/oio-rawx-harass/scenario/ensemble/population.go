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

	"golang.org/x/sync/errgroup"
	"openio-sds/tools/oio-rawx-harass/client"
	"openio-sds/tools/oio-rawx-harass/scenario"
)

type Population struct {
	scenario.AbstractPopulation

	targets []client.RawxTarget
	pops    []scenario.Runnable
}

// Run implements scenario.Runnable.Run
func (b *Population) Warmup(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error {
	b.Log(ctx).Debug("warmup")

	if stats == nil {
		return errors.New("Missing stats")
	}
	if len(b.pops) == 0 {
		return errors.New("missing population")
	}

	g, ctx := errgroup.WithContext(ctx)
	for i, _ := range b.pops {
		pop := &b.pops[i]

		realTgt := tgt
		if realTgt.Empty() {
			realTgt = &b.targets[i]
		}
		if realTgt.Empty() {
			return errors.New("no RAWX specified")
		}

		g.Go(func() error { return (*pop).Warmup(ctx, realTgt, stats) })
	}
	return g.Wait()
}

func (b *Population) Run(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error {
	b.Log(ctx).Debug("run")

	if stats == nil {
		return errors.New("Missing stats")
	}
	if len(b.pops) == 0 {
		return errors.New("missing population")
	}

	g, ctx := errgroup.WithContext(ctx)
	for i, _ := range b.pops {
		pop := &b.pops[i]

		// Override local targets if global targets have been provided
		realTgt := tgt
		if realTgt.Empty() {
			realTgt = &b.targets[i]
		}
		if realTgt.Empty() {
			return errors.New("no RAWX specified")
		}

		g.Go(func() error {
			return (*pop).Run(ctx, realTgt, stats)
		})
	}
	return g.Wait()
}

func (b *Population) Cleanup(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error {
	b.Log(ctx).Debug("cleanup")

	if stats == nil {
		return errors.New("Missing stats")
	}
	if len(b.pops) == 0 {
		return errors.New("missing population")
	}

	g, ctx := errgroup.WithContext(ctx)
	for i, _ := range b.pops {
		pop := &b.pops[i]

		// Override local targets if global targets have been provided
		realTgt := tgt
		if realTgt.Empty() {
			realTgt = &b.targets[i]
		}
		if realTgt.Empty() {
			return errors.New("no RAWX specified")
		}

		g.Go(func() error { return (*pop).Cleanup(ctx, realTgt, stats) })
	}
	return g.Wait()
}
