// OpenIO SDS Go rawx
// Copyright (C) 2015-2018 OpenIO SAS
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

package main

import (
	"fmt"
	"net/http"
	"sync"
)

const (
	BytesRead = iota
	BytesWritten

	Hits2XX
	Hits403
	Hits404
	Hits4XX
	Hits5XX

	HitsPut
	HitsCopy
	HitsGet
	HitsHead
	HitsDel
	HitsList
	HitsOther
	HitsTotal

	TimePut
	TimeCopy
	TimeGet
	TimeHead
	TimeDel
	TimeList
	TimeOther
	TimeTotal

	LastStat
)

var statNames = [LastStat]string{
	"rep.bread",
	"rep.bwritten",

	"rep.hits.2xx",
	"rep.hits.403",
	"rep.hits.404",
	"rep.hits.4xx",
	"rep.hits.5xx",

	"rep.hits.put",
	"rep.hits.get",
	"rep.hits.head",
	"rep.hits.del",
	"rep.hits.stat",
	"rep.hits.other",
	"rep.hits",

	"rep.time.put",
	"rep.time.get",
	"rep.time.head",
	"rep.time.del",
	"rep.time.stat",
	"rep.time.other",
	"rep.time",
}

type StatSet struct {
	lock   sync.RWMutex
	values [LastStat]uint64
}

var counters, timers StatSet

func (ss *StatSet) Increment(which int) {
	ss.lock.Lock()
	defer ss.lock.Unlock()

	if which < 0 || which >= LastStat {
		panic("BUG: stat does not exist")
	}
	ss.values[which]++
}

func (ss *StatSet) Add(which int, inc uint64) {
	ss.lock.Lock()
	defer ss.lock.Unlock()

	if which < 0 || which >= LastStat {
		panic("BUG: stat does not exist")
	}
	ss.values[which] += inc
}

func (ss *StatSet) Get() [LastStat]uint64 {
	ss.lock.RLock()
	defer ss.lock.RUnlock()

	var tab [LastStat]uint64
	tab = ss.values
	return tab
}

type statHandler struct {
	rawx *rawxService
}

// FIXME(jfs): Shouldn't a HEAD return the Content-Length of the GET on the
// same resource, but without the body?
func doCheckStats(rr *rawxRequest) {
	rr.rep.Header().Set("Accept-Ranges", "none")
	rr.rep.Header().Set("Content-Length", "0")
	rr.replyCode(http.StatusOK)
}

func doGetStats(rr *rawxRequest) {
	allCounters := counters.Get()
	allTimers := timers.Get()

	rr.replyCode(http.StatusOK)
	for i, n := range statNames {
		rr.rep.Write([]byte(fmt.Sprintf("timer.%s %v\n", n, allTimers[i])))
		rr.rep.Write([]byte(fmt.Sprintf("counter.%s %v\n", n, allCounters[i])))
	}
}

func (rr *rawxRequest) serveStat(rep http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		doGetStats(rr)
	case "HEAD":
		doCheckStats(rr)
	default:
		rr.replyCode(http.StatusMethodNotAllowed)
	}
}
