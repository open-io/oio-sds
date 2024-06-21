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
	"time"
)

type FrequencyGetter func() int

func AperiodicTicker(ctx context.Context, out chan bool, frequency FrequencyGetter) {
	done := ctx.Done()
	stepper := time.NewTicker(time.Second)

	hz := frequency()
	if hz <= 0 {
		hz = 1
	}
	ticker := time.NewTicker(time.Second / time.Duration(hz))

	for {
		select {
		case <-done:
			ticker.Stop()
			stepper.Stop()
			close(out)
			return
		case <-stepper.C:
			ticker.Stop()
			hz = frequency()
			if hz <= 0 {
				hz = 1
			}
			ticker = time.NewTicker(time.Second / time.Duration(hz))
		case <-ticker.C:
			out <- true
		}
	}
}
