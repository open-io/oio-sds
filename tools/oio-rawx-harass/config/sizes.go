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

package config

import (
	"context"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
	"openio-sds/tools/oio-rawx-harass/distribution"
	"openio-sds/tools/oio-rawx-harass/utils"
)

type SizesConfiguration map[string]distribution.Int64Histogram

func NewSizesConfig() *SizesConfiguration {
	sz := make(SizesConfiguration)
	return &sz
}

func (cfg SizesConfiguration) LoadReader(in io.Reader) error {
	decoder := yaml.NewDecoder(in)
	if err := decoder.Decode(cfg); err != nil {
		return err
	}

	return nil
}

func (cfg SizesConfiguration) LoadPath(ctx context.Context, path string) error {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return fmt.Errorf("open error with path '%s': %w", path, err)
	}

	if err = cfg.LoadReader(f); err != nil {
		return err
	} else {
		utils.Log(ctx).WithField("path", path).WithField("count", len(cfg)).Debug("sizes loaded")
		return nil
	}
}

func LoadSizes(ctx context.Context, path string) (*SizesConfiguration, error) {
	cfg := NewSizesConfig()
	err := cfg.LoadPath(ctx, path)
	return cfg, err
}
