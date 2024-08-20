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

package utils

import (
	"context"
	"testing"
	"time"
)

func TestAperiodicTicker(t *testing.T) {
	N := 3
	hz := 2
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(N)*time.Second+100*time.Millisecond)
	defer cancel()
	out := make(chan bool)

	go func() {
		AperiodicTicker(ctx, out, func() int { return hz })
		close(out)
	}()

	total := 0
	for _ = range out {
		total++
	}
	if total != N*hz {
		t.Errorf("got %d, want %d", total, N*hz)
	}
}
