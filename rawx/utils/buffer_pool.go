// OpenIO SDS Go rawx
// Copyright (C) 2020 OpenIO SAS
// Copyright (C) 2023-2024 OVH SAS
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

package utils

// BufferPool stores already allocated memory buffers.
// Notice there is no limit on the number of buffer this module can allocate.
type BufferPool interface {
	Acquire() []byte
	Release(buf []byte)
}

type unisizeBufferPool struct {
	pool chan []byte
	size int
}

func NewBufferPool(max, size int) BufferPool {
	nb := max / size
	if nb < 1 {
		nb = 1
	}
	return &unisizeBufferPool{pool: make(chan []byte, nb), size: size}
}

func (p *unisizeBufferPool) Acquire() []byte {
	select {
	// Try to take an already allocated buffer from the pool
	case buf := <-p.pool:
		return buf[:cap(buf)]
	// Allocate a new buffer
	default:
		return make([]byte, p.size, p.size)
	}
}

func (p *unisizeBufferPool) Release(buf []byte) {
	select {
	// Try to put the buffer back in the pool
	case p.pool <- buf:
	// Free the buffer if the pool is full
	default:
	}
}
