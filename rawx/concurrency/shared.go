// OpenIO SDS Go rawx
// Copyright (C) 2025 OVH SAS
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

package concurrency

var sharedState ConcurrencyState

func GetConcurrency() ConcurrencyState { return sharedState }

func BeginPUT() { sharedState.BeginPUT() }
func BeginGET() { sharedState.BeginGET() }
func BeginDEL() { sharedState.BeginDEL() }

func EndPUT() { sharedState.EndPUT() }
func EndGET() { sharedState.EndGET() }
func EndDEL() { sharedState.EndDEL() }

func CountPUT(action func()) { sharedState.CountPUT(action) }
func CountGET(action func()) { sharedState.CountGET(action) }
func CountDEL(action func()) { sharedState.CountDEL(action) }
