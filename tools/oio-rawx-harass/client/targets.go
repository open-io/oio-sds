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

package client

type RawxTarget struct {
	RawxUrl []string
}

func (tgt *RawxTarget) Empty() bool {
	return tgt == nil || len(tgt.RawxUrl) == 0
}

func NoTarget() RawxTarget {
	return RawxTarget{RawxUrl: make([]string, 0)}
}

func MakeTargets(urls []string) RawxTarget {
	tgt := RawxTarget{
		RawxUrl: make([]string, len(urls)),
	}
	copy(tgt.RawxUrl, urls)
	return tgt
}
