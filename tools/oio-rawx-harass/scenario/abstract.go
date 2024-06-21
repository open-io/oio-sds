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
	log "github.com/sirupsen/logrus"
	"openio-sds/tools/oio-rawx-harass/client"
)

type AbstractPopulation struct {
	Id string
}

func (pop *AbstractPopulation) SetId(id string) {
	pop.Id = id
}

func (pop *AbstractPopulation) Log(ctx context.Context) *log.Entry {
	return log.WithField("_p", pop.Id).WithContext(ctx)
}

func (pop *AbstractPopulation) Warmup(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error {
	if tgt.Empty() {
		return errors.New("Missing target")
	}
	if stats == nil {
		return errors.New("Missing stats")
	}
	pop.Log(ctx).Debug("warmup skipped")
	return nil
}

func (pop *AbstractPopulation) Cleanup(ctx context.Context, tgt *client.RawxTarget, stats *client.Stats) error {
	if tgt.Empty() {
		return errors.New("Missing target")
	}
	if stats == nil {
		return errors.New("Missing stats")
	}
	pop.Log(ctx).Debug("cleanup skipped")
	return nil
}
