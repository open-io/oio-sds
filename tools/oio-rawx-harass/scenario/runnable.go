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

package scenario

import (
	"context"
	"openio-sds/tools/oio-rawx-harass/client"
	"os"
)

type Runnable interface {
	// Run instanciates a new stress test. It should be callable concurrently, whatever the implementation.
	// Also, the stats should be updated using atomic operations, whatever the implementation.
	Run(ctx context.Context, tgt client.RawxTarget, stats *client.Stats) error
}

// Run spawns a new stress for the given Runnable scenario, with a fresh stats holder, toward the given targets.
// The targets are explicitely passed bby value to avoid the list to be altered by another stress run.
// The dedicated stats are then returned.
func Run(ctx context.Context, tgt client.RawxTarget, pop Runnable) (error, client.Stats) {
	stats := client.Stats{}
	err := pop.Run(ctx, tgt, &stats)
	return err, stats
}

// RunAndPrint spawns a stress run and dumps a human-readable representation of the stats to the standard output
func RunAndPrint(ctx context.Context, tgt client.RawxTarget, pop Runnable) error {
	err, stats := Run(ctx, tgt, pop)
	if err == nil {
		err = stats.WriteHuman(os.Stdout)
	}
	return err
}
