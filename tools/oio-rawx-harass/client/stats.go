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

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sync/atomic"
	"time"
)

type Stats struct {
	ErrorPut uint64 // number of failed upload requests
	ErrorGet uint64 // number of failed download requests
	ErrorDel uint64 // number of failed delete requests
	HitsPut  uint64 // total number of upload requests
	HitsGet  uint64 // total number of download requests
	HitsDel  uint64 // total number of delete requests
	TimePut  uint64 // cumulated time spent puting chunks
	TimeGet  uint64 // cumulated time spent getting chunks
	TimeDel  uint64 // cumulated time spent deleting chunks
	BytesPut uint64 // number of bytes sent, as PUT payloads
	BytesGet uint64 // number of bytes received, as GET payloads
}

func (s *Stats) Add(rhs Stats) {
	atomic.AddUint64(&s.ErrorPut, rhs.ErrorPut)
	atomic.AddUint64(&s.ErrorGet, rhs.ErrorGet)
	atomic.AddUint64(&s.ErrorDel, rhs.ErrorDel)
	atomic.AddUint64(&s.HitsPut, rhs.HitsPut)
	atomic.AddUint64(&s.HitsGet, rhs.HitsGet)
	atomic.AddUint64(&s.HitsDel, rhs.HitsDel)
	atomic.AddUint64(&s.TimePut, rhs.TimePut)
	atomic.AddUint64(&s.TimeGet, rhs.TimeGet)
	atomic.AddUint64(&s.TimeDel, rhs.TimeDel)
	atomic.AddUint64(&s.BytesPut, rhs.BytesPut)
	atomic.AddUint64(&s.BytesGet, rhs.BytesGet)
}

func (st *Stats) WriteHuman(out io.Writer) error {
	s := uint64(time.Second.Nanoseconds())
	us := uint64(time.Microsecond.Nanoseconds())

	buf := bytes.Buffer{}

	if st.HitsPut > 0 {
		fmt.Fprintf(&buf, "put: %d hits %d err %d bytes %d us/hit %d B/s\n",
			st.HitsPut, st.ErrorPut, st.BytesPut,
			(st.TimePut/st.HitsPut)/us,
			int64(float64(s)*(float64(st.BytesPut)/float64(st.TimePut))))
	} else {
		fmt.Fprintf(&buf, "put: %d hits %d err %d bytes %f us/hit %d B/s\n",
			0, 0, 0, math.NaN(), 0)
	}

	if st.HitsGet > 0 {
		fmt.Fprintf(&buf, "get: %d hits %d err %d bytes %d us/hit %d B/s\n",
			st.HitsGet, st.ErrorGet, st.BytesGet,
			(st.TimeGet/st.HitsGet)/us,
			int64(float64(s)*(float64(st.BytesGet)/float64(st.TimeGet))))
	} else {
		fmt.Fprintf(&buf, "get: %d hits %d err %d bytes %f us/hit %d B/s\n",
			0, 0, 0, math.NaN(), 0)
	}

	if st.HitsDel > 0 {
		fmt.Fprintf(&buf, "del: %d hits %d err %d us/hit\n",
			st.HitsDel, st.ErrorDel, (st.TimeDel/st.HitsDel)/us)
	} else {
		fmt.Fprintf(&buf, "del: %d hits %d err %f us/hit\n",
			0, 0, math.NaN())
	}

	_, err := buf.WriteTo(out)
	return err
}

func (st *Stats) WriteJson(out io.Writer) error {
	return json.NewEncoder(out).Encode(st)
}
