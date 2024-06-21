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

package proba

import "time"

func NewPopulationStandard() *PopulationConfig {
	return &PopulationConfig{
		MaxWorkers:               8,
		Duration:                 time.Hour,
		AverageGetFrequency:      1.0,
		AverageCreationFrequency: 10,
		LifeExpectancy:           5 * time.Minute,
		LifeDeviation:            10 * time.Minute,
	}
}

func NewPopulationIA() *PopulationConfig {
	return &PopulationConfig{
		MaxWorkers:               8,
		Duration:                 time.Hour,
		AverageGetFrequency:      0.3,
		AverageCreationFrequency: 3,
		LifeExpectancy:           5 * time.Minute,
		LifeDeviation:            10 * time.Minute,
	}

}

func NewPopulationGlacier() *PopulationConfig {
	return &PopulationConfig{
		MaxWorkers:               8,
		Duration:                 time.Hour,
		AverageGetFrequency:      0.001,
		AverageCreationFrequency: 2,
		LifeExpectancy:           300 * time.Minute,
		LifeDeviation:            5 * time.Minute,
	}
}

func NewPopulationProbabilistic() *PopulationConfig {
	return &PopulationConfig{
		MaxWorkers:               8,
		Duration:                 time.Minute,
		AverageGetFrequency:      0.1,
		AverageCreationFrequency: 1,
		LifeExpectancy:           30 * time.Second,
		LifeDeviation:            5 * time.Second,
	}
}
