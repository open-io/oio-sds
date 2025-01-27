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

import "sync/atomic"

type ConcurrencyState struct {
	Put uint32
	Get uint32
	Del uint32
}

func doBegin(u32 *uint32) { atomic.AddUint32(u32, 1) }
func doEnd(u32 *uint32)   { atomic.AddUint32(u32, ^uint32(0)) }

func (c *ConcurrencyState) BeginPUT() { doBegin(&c.Put) }
func (c *ConcurrencyState) BeginGET() { doBegin(&c.Get) }
func (c *ConcurrencyState) BeginDEL() { doBegin(&c.Del) }

func (c *ConcurrencyState) EndPUT() { doEnd(&c.Put) }
func (c *ConcurrencyState) EndGET() { doEnd(&c.Get) }
func (c *ConcurrencyState) EndDEL() { doEnd(&c.Del) }

func (c *ConcurrencyState) CountPUT(action func()) {
	c.BeginPUT()
	defer c.EndPUT()
	action()
}

func (c *ConcurrencyState) CountGET(action func()) {
	c.BeginGET()
	defer c.EndGET()
	action()
}

func (c *ConcurrencyState) CountDEL(action func()) {
	c.BeginDEL()
	defer c.EndDEL()
	action()
}
