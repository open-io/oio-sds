// OpenIO SDS Go rawx
// Copyright (C) 2020 OpenIO SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public
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

package main

type bufferPool interface {
	Acquire() []byte
	Release(buf []byte)
}

type unisizeBufferPool struct {
	pool chan []byte
	size int
}

func newBufferPool(max, size int) bufferPool {
	nb := max / size
	if nb < 1 {
		nb = 1
	}
	return &unisizeBufferPool{pool: make(chan []byte, nb), size: size}
}

func (p *unisizeBufferPool) Acquire() []byte {
	select {
	case buf := <-p.pool:
		return buf[:cap(buf)]
	default:
		return make([]byte, p.size, p.size)
	}
}

func (p *unisizeBufferPool) Release(buf []byte) {
	select {
	case p.pool <- buf: // reused
	default: // freed
	}
}
