// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2021-2024 OVH SAS
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

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"openio-sds/rawx/logger"
	"openio-sds/rawx/utils"
)

type statInfo struct {
	ReqTimeAll   uint64 `tag:"req.time"`
	ReqTimePut   uint64 `tag:"req.time.put"`
	ReqTimePost  uint64 `tag:"req.time.post"`
	ReqTimeCopy  uint64 `tag:"req.time.copy"`
	ReqTimeGet   uint64 `tag:"req.time.get"`
	ReqTimeHead  uint64 `tag:"req.time.head"`
	ReqTimeDel   uint64 `tag:"req.time.del"`
	ReqTimeStat  uint64 `tag:"req.time.stat"`
	ReqTimeInfo  uint64 `tag:"req.time.info"`
	ReqTimeRaw   uint64 `tag:"req.time.raw"`
	ReqTimeOther uint64 `tag:"req.time.other"`

	ReqHitsAll   uint64 `tag:"req.hits"`
	ReqHitsPut   uint64 `tag:"req.hits.put"`
	ReqHitsPost  uint64 `tag:"req.hits.post"`
	ReqHitsCopy  uint64 `tag:"req.hits.copy"`
	ReqHitsGet   uint64 `tag:"req.hits.get"`
	ReqHitsHead  uint64 `tag:"req.hits.head"`
	ReqHitsDel   uint64 `tag:"req.hits.del"`
	ReqHitsStat  uint64 `tag:"req.hits.stat"`
	ReqHitsInfo  uint64 `tag:"req.hits.info"`
	ReqHitsRaw   uint64 `tag:"req.hits.raw"`
	ReqHitsOther uint64 `tag:"req.hits.other"`

	RepHits2XX   uint64 `tag:"rep.hits.2xx"`
	RepHits4XX   uint64 `tag:"rep.hits.4xx"`
	RepHits5XX   uint64 `tag:"rep.hits.5xx"`
	RepHitsOther uint64 `tag:"rep.hits.other"`
	RepHits403   uint64 `tag:"rep.hits.403"`
	RepHits404   uint64 `tag:"rep.hits.404"`

	RepBread    uint64 `tag:"rep.bread"`
	RepBwritten uint64 `tag:"rep.bwritten"`
}

var counters statInfo

func incrementStatReq(rr *rawxRequest) (uint64, uint64) {
	spent := uint64(time.Since(rr.startTime).Nanoseconds() / 1000)
	ttfb := uint64(rr.TTFB.Nanoseconds() / 1000)
	atomic.AddUint64(&counters.ReqTimeAll, spent)
	atomic.AddUint64(&counters.ReqHitsAll, 1)

	if rr.status == 0 {
		atomic.AddUint64(&counters.RepHitsOther, 1)
		return spent, ttfb
	}
	switch rr.status / 100 {
	case 2:
		atomic.AddUint64(&counters.RepHits2XX, 1)
	case 4:
		atomic.AddUint64(&counters.RepHits4XX, 1)
		switch rr.status {
		case 403:
			atomic.AddUint64(&counters.RepHits403, 1)
		case 404:
			atomic.AddUint64(&counters.RepHits404, 1)
		}
	case 5:
		atomic.AddUint64(&counters.RepHits5XX, 1)
	default:
		atomic.AddUint64(&counters.RepHitsOther, 1)
	}

	return spent, ttfb
}

func IncrementStatReqMethod(rr *rawxRequest) (uint64, uint64) {
	switch rr.req.Method {
	case "PUT":
		return IncrementStatReqPut(rr)
	case "POST":
		return IncrementStatReqPost(rr)
	case "COPY":
		return IncrementStatReqCopy(rr)
	case "HEAD":
		return IncrementStatReqHead(rr)
	case "GET":
		return IncrementStatReqGet(rr)
	case "DELETE":
		return IncrementStatReqDel(rr)
	default:
		return IncrementStatReqOther(rr)
	}
}

func IncrementStatReqPut(rr *rawxRequest) (uint64, uint64) {
	spent, ttfb := incrementStatReq(rr)
	atomic.AddUint64(&counters.ReqTimePut, spent)
	atomic.AddUint64(&counters.ReqHitsPut, 1)
	atomic.AddUint64(&counters.RepBwritten, rr.bytesIn)
	return spent, ttfb
}

func IncrementStatReqPost(rr *rawxRequest) (uint64, uint64) {
	spent, ttfb := incrementStatReq(rr)
	atomic.AddUint64(&counters.ReqTimePost, spent)
	atomic.AddUint64(&counters.ReqHitsPost, 1)
	return spent, ttfb
}

func IncrementStatReqCopy(rr *rawxRequest) (uint64, uint64) {
	spent, ttfb := incrementStatReq(rr)
	atomic.AddUint64(&counters.ReqTimeCopy, spent)
	atomic.AddUint64(&counters.ReqHitsCopy, 1)
	return spent, ttfb
}

func IncrementStatReqHead(rr *rawxRequest) (uint64, uint64) {
	spent, ttfb := incrementStatReq(rr)
	atomic.AddUint64(&counters.ReqTimeHead, spent)
	atomic.AddUint64(&counters.ReqHitsHead, 1)
	return spent, ttfb
}

func IncrementStatReqGet(rr *rawxRequest) (uint64, uint64) {
	spent, ttfb := incrementStatReq(rr)
	atomic.AddUint64(&counters.ReqTimeGet, spent)
	atomic.AddUint64(&counters.ReqHitsGet, 1)
	atomic.AddUint64(&counters.RepBread, rr.bytesOut)
	return spent, ttfb
}

func IncrementStatReqDel(rr *rawxRequest) (uint64, uint64) {
	spent, ttfb := incrementStatReq(rr)
	atomic.AddUint64(&counters.ReqTimeDel, spent)
	atomic.AddUint64(&counters.ReqHitsDel, 1)
	return spent, ttfb
}

func IncrementStatReqStat(rr *rawxRequest) (uint64, uint64) {
	spent, ttfb := incrementStatReq(rr)
	atomic.AddUint64(&counters.ReqTimeStat, spent)
	atomic.AddUint64(&counters.ReqHitsStat, 1)
	return spent, ttfb
}

func IncrementStatReqInfo(rr *rawxRequest) (uint64, uint64) {
	spent, ttfb := incrementStatReq(rr)
	atomic.AddUint64(&counters.ReqTimeInfo, spent)
	atomic.AddUint64(&counters.ReqHitsInfo, 1)
	return spent, ttfb
}

func IncrementStatReqOther(rr *rawxRequest) (uint64, uint64) {
	spent, ttfb := incrementStatReq(rr)
	atomic.AddUint64(&counters.ReqTimeOther, spent)
	atomic.AddUint64(&counters.ReqHitsOther, 1)
	return spent, ttfb
}

func doGetStats(rr *rawxRequest) {
	bb := bytes.Buffer{}
	values := reflect.ValueOf(&counters).Elem()
	keys := values.Type()
	for i := 0; i < values.NumField(); i++ {
		value := values.Field(i).Interface()
		key := keys.Field(i).Tag.Get("tag")
		bb.WriteString("counter ")
		bb.WriteString(key)
		bb.WriteRune(' ')
		bb.WriteString(utils.Utoa(value.(uint64)))
		bb.WriteRune('\n')
	}

	bb.WriteString("config volume ")
	bb.WriteString(rr.rawx.path)
	bb.WriteRune('\n')

	if rr.rawx.id != "" {
		bb.WriteString("config service_id ")
		bb.WriteString(rr.rawx.id)
		bb.WriteRune('\n')
	}

	rr.replyCode(http.StatusOK)
	rr.TTFB = time.Since(rr.startTime)
	rr.rep.Write(bb.Bytes())
}

func doGetStatsPrometheus(rr *rawxRequest) {
	bb := bytes.Buffer{}
	values := reflect.ValueOf(&counters).Elem()
	keys := values.Type()

	labels := fmt.Sprintf(`{service_id="%s",volume="%s",namespace="%s"`, rr.rawx.getURL(), rr.rawx.path, rr.rawx.ns)

	for i := 0; i < values.NumField(); i++ {
		value := values.Field(i).Interface()
		key := keys.Field(i).Tag.Get("tag")
		tags := strings.Split(key, ".")
		if len(tags) == 0 {
			continue
		}
		bb.WriteString("rawx")
		switch tags[0] {

		// handle req.* tags
		case "req":
			bb.WriteString("_requests")
			if len(tags) == 2 {
				tags = append(tags, "all")
			}
			switch tags[1] {
			case "time":
				bb.WriteString("_duration_ms_total")
			case "hits":
				bb.WriteString("_hits_total")
			default:
				continue
			}
			bb.WriteString(labels)
			bb.WriteString(`,method="`)
			bb.WriteString(tags[2])
			bb.WriteString(`"}`)

		// handle rep.* tags
		case "rep":
			bb.WriteString("_responses")
			switch tags[1] {
			case "hits":
				if len(tags) < 3 {
					continue
				}
				bb.WriteString("_hits_total")
				bb.WriteString(labels)
				bb.WriteString(`,status_code="`)
				bb.WriteString(tags[2])
				bb.WriteString(`"}`)

			// bread is the sum of the bytes the client has read
			// which means that this is the sum of byte rawx as sent to clients
			// in this case, direction label is set to `out`
			// yes this is confusing ... don't ask
			case "bread":
				bb.WriteString("_size_byte_total")
				bb.WriteString(labels)
				bb.WriteString(`,direction="out"}`)

			// bwritten is the sum of the bytes written to disk
			// which means that this is the sum of byte rawx as received from clients
			// in this case, direction label is set to `in`
			// yes this is confusing ... don't ask
			case "bwritten":
				bb.WriteString("_size_byte_total")
				bb.WriteString(labels)
				bb.WriteString(`,direction="in"}`)
			default:
				continue
			}
		default:
			continue
		}
		bb.WriteRune(' ')
		bb.WriteString(utils.Utoa(value.(uint64)))
		bb.WriteRune('\n')
	}

	rr.replyCode(http.StatusOK)
	rr.TTFB = time.Since(rr.startTime)
	rr.rep.Write(bb.Bytes())
}

func (rr *rawxRequest) serveStat() {
	if err := rr.drain(); err != nil {
		rr.replyError("", err)
		return
	}

	var spent uint64
	var ttfb uint64
	if !rr.rawx.isIOok() {
		rr.replyIoError(rr.rawx)
	} else {
		switch rr.req.Method {
		case "GET", "HEAD":
			if rr.req.URL.Query().Get("format") == "prometheus" {
				doGetStatsPrometheus(rr)
			} else {
				doGetStats(rr)
			}
		default:
			rr.replyCode(http.StatusMethodNotAllowed)
		}
	}
	spent, ttfb = IncrementStatReqStat(rr)

	if logger.IsVerbose() {
		logger.LogHttp(logger.AccessLogEvent{
			Status:    rr.status,
			TimeSpent: spent,
			BytesIn:   rr.bytesIn,
			BytesOut:  rr.bytesOut,
			Method:    rr.req.Method,
			Local:     rr.req.Host,
			Peer:      rr.req.RemoteAddr,
			Path:      rr.req.URL.Path,
			ReqId:     rr.reqid,
			TLS:       rr.req.TLS != nil,
			TTFB:      ttfb,
		})
	}
}
