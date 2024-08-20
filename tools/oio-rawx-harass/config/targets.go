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
	"gopkg.in/yaml.v3"
	"io"
	"openio-sds/tools/oio-rawx-harass/state"
	"openio-sds/tools/oio-rawx-harass/utils"
	"os"
	"strings"
)

type RawxTarget struct {
	url string
	st  *state.State
}

type RawxTargets struct {
	Targets []*RawxTarget
}

type rawxTargetConfig struct {
	RawxUrl []string `yaml:"targets"`
}

func NewTargets(ctx context.Context, datadir string, urls []string) (*RawxTargets, error) {
	targets := &RawxTargets{
		Targets: []*RawxTarget{},
	}
	var err error
	for _, url := range urls {
		path := fmt.Sprintf("%s/state-%s", datadir, url)
		tgt := &RawxTarget{url: url}
		tgt.st, err = state.Open(path)
		if err != nil {
			return nil, err
		} else {
			utils.Log(ctx).WithField("url", url).WithField("path", path).Info("State open")
			targets.Targets = append(targets.Targets, tgt)
		}
	}
	return targets, nil
}

func LoadTargetsReader(ctx context.Context, datadir string, in io.Reader) (*RawxTargets, error) {
	cfg := &rawxTargetConfig{}

	decoder := yaml.NewDecoder(in)
	if err := decoder.Decode(cfg); err != nil {
		return nil, err
	}

	return NewTargets(ctx, datadir, cfg.RawxUrl)
}

func LoadTargetsPath(ctx context.Context, datadir string, path string) (*RawxTargets, error) {
	f, err := os.Open(path)
	defer f.Close()
	if err != nil {
		return nil, fmt.Errorf("open error with path '%s': %w", path, err)
	}

	return LoadTargetsReader(ctx, datadir, f)
}

func (tgt *RawxTargets) Close() error {
	for _, t := range tgt.Targets {
		t.Close()
	}
	return nil
}

func (tgt *RawxTargets) Empty() bool { return tgt == nil || len(tgt.Targets) == 0 }

func (tgt *RawxTargets) Count() int { return len(tgt.Targets) }

func (tgt *RawxTargets) Debug() string {
	urls := make([]string, 0)
	for _, target := range tgt.Targets {
		urls = append(urls, target.url)
	}
	return strings.Join(urls, ",")
}

func (tgt *RawxTargets) Urls() chan string {
	out := make(chan string, 4)

	go func(c chan string, tab []*RawxTarget) {
		for _, x := range tab {
			c <- x.url
		}
		close(c)
	}(out, tgt.Targets)

	return out
}

func (tgt *RawxTargets) Poll() uint32 {
	return uint32(utils.RandIntRange(0, len(tgt.Targets)))
}

func (tgt *RawxTargets) Get(rx uint32) *RawxTarget {
	return tgt.Targets[rx]
}

func (tgt *RawxTargets) Find(url string) (uint32, *RawxTarget) {
	for idx, x := range tgt.Targets {
		if x.URL() == url {
			return uint32(idx), x
		}
	}
	panic("target not found")
}

func (t *RawxTarget) Close() {
	if t.st != nil {
		_ = t.st.Close()
		t.st = nil
	}
}

func (t *RawxTarget) URL() string { return t.url }

func (t *RawxTarget) Iterate(ctx context.Context) chan state.Record {
	producer := func(out chan state.Record) {
		t.st.Scan(ctx, out)
		close(out)
	}
	out := make(chan state.Record, 8)
	go producer(out)
	return out
}

func (t *RawxTarget) Save(chunk string) error { return t.st.Insert(chunk) }

func (t *RawxTarget) Delete(chunk string) error { return t.st.Delete(chunk) }
