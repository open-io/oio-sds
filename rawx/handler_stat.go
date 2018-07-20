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
	BytesRead    = iota
	BytesWritten = iota

	Hits2XX = iota
	Hits403 = iota
	Hits404 = iota
	Hits4XX = iota
	Hits5XX = iota

	HitsPut   = iota
	HitsGet   = iota
	HitsHead  = iota
	HitsDel   = iota
	HitsList  = iota
	HitsOther = iota
	HitsTotal = iota

	TimePut   = iota
	TimeGet   = iota
	TimeHead  = iota
	TimeDel   = iota
	TimeList  = iota
	TimeOther = iota
	TimeTotal = iota

	LastStat = iota
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

func (self *statHandler) ServeHTTP(rep http.ResponseWriter, req *http.Request) {
	self.rawx.serveHTTP(rep, req, func(rr *rawxRequest) {
		switch req.Method {
		case "GET":
			doGetStats(rr)
		case "HEAD":
			doCheckStats(rr)
		default:
			rr.replyCode(http.StatusMethodNotAllowed)
		}
	})
}
