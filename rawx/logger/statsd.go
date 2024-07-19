// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2021-2024 OVH SAS
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

package logger

import (
	"github.com/cactus/go-statsd-client/v5/statsd"
	"openio-sds/rawx/defs"
)

// The statsd client
var statsdClient statsd.Statter

func InitStatsd(addr string, prefix string) {
	var err error

	if addr == "" {
		return
	}
	if prefix == "" {
		prefix = defs.StatsdPrefixDefault
	}

	config := &statsd.ClientConfig{
		Address: addr,
		Prefix:  prefix,
	}

	statsdClient, err = statsd.NewClientWithConfig(config)
	if err != nil {
		LogError("Unable to init statsd: %v", err)
	}
}
