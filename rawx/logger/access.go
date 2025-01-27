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

package logger

import (
	"bytes"
	"fmt"
	"log"
	"openio-sds/rawx/concurrency"
)

type AccessLogEvent struct {
	Pid       int
	Status    int
	BytesIn   uint64
	BytesOut  uint64
	TimeSpent uint64
	Method    string
	Local     string
	Peer      string
	Path      string
	ReqId     string
	TLS       bool
	TTFB      uint64

	Concurrency concurrency.ConcurrencyState
}

func (evt AccessLogEvent) String() string {
	evt.Pid = Pid
	var output bytes.Buffer
	err := AccessLogTemplate.Execute(&output, evt)

	if err != nil {
		log.Printf("Error while executing AccessLogTemplate: %v", err)
		return ""
	}
	return output.String()
}

func LogHttp(evt AccessLogEvent) {

	if statsdClient != nil {
		prefix := fmt.Sprintf("request.%s.%d", evt.Method, evt.Status)
		// .TimeSpent and .TTFB are in µs while statsd expects ms
		statsdClient.Timing(fmt.Sprintf("%s.duration", prefix), int64(evt.TimeSpent/1000), 1.0)
		if evt.Method == "GET" {
			statsdClient.Timing(fmt.Sprintf("%s.ttfb", prefix), int64(evt.TTFB/1000), 1.0)
		}
		statsdClient.Inc(fmt.Sprintf("%s.in.xfer", prefix), int64(evt.BytesIn), 1.0)
		statsdClient.Inc(fmt.Sprintf("%s.out.xfer", prefix), int64(evt.BytesOut), 1.0)
	}

	logger.WriteAccess(evt.String())
}
