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

	log "github.com/sirupsen/logrus"
)

type Progress struct {
	tag string

	lastPrint time.Time
	period    time.Duration

	TotalPut uint64
	TotalGet uint64
	TotalDel uint64
}

func NewProgress(clock time.Time, tag string) Progress {
	return Progress{
		tag:       tag,
		lastPrint: clock,
		period:    5 * time.Second,
	}
}

func (p *Progress) Print(ctx context.Context, clock time.Time) {
	log.WithContext(ctx).WithFields(log.Fields{
		"_t":      clock,
		"_p":      p.tag,
		"started": p.TotalPut,
		"fetched": p.TotalGet,
		"deleted": p.TotalDel,
	}).Info("progress")
	p.lastPrint = clock
}

func (p *Progress) PrintPeriodically(ctx context.Context, clock time.Time) {
	if clock.Sub(p.lastPrint) > p.period {
		p.Print(ctx, clock)
	}
}
