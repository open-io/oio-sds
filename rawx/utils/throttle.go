// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2020-2024 OVH SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package utils

import (
	"sync/atomic"
	"time"
)

type Throttle interface {
	Ok() bool
}

type periodicThrottle struct {
	nanoLast int64
	period   int64
}

func NewPeriodicThrottle(period int64) Throttle {
	return &periodicThrottle{period: period}
}

func (pt *periodicThrottle) Ok() bool {
	nanoNow := time.Now().UnixNano()
	nanoThen := pt.nanoLast
	if nanoThen == 0 || nanoNow-nanoThen > pt.period {
		return atomic.CompareAndSwapInt64(&pt.nanoLast, nanoThen, nanoNow)
	}
	return false
}
