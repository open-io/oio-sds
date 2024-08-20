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
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"openio-sds/tools/oio-rawx-harass/client"
	"openio-sds/tools/oio-rawx-harass/utils"
)

type AbstractPopulation struct {
	Id string
}

func (pop *AbstractPopulation) SetId(id string) {
	pop.Id = id
}

func (pop *AbstractPopulation) Log(ctx context.Context) *log.Entry {
	return utils.Log(ctx).WithField("_p", pop.Id)
}

func (pop *AbstractPopulation) LogT(ctx context.Context, t time.Time) *log.Entry {
	return utils.LogT(ctx, t).WithField("_p", pop.Id)
}

func (pop *AbstractPopulation) Warmup(ctx context.Context, stats *client.Stats) error {
	if stats == nil {
		return errors.New("Missing stats")
	}
	pop.Log(ctx).Debug("warmup skipped")
	return nil
}

func (pop *AbstractPopulation) Cleanup(ctx context.Context, stats *client.Stats) error {
	if stats == nil {
		return errors.New("Missing stats")
	}
	pop.Log(ctx).Debug("cleanup skipped")
	return nil
}
