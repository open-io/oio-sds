// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
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

import (
	"bytes"
	"net/http"
)

func doGetInfo(rr *rawxRequest) {
	bb := bytes.Buffer{}
	bb.WriteString("namespace ")
	bb.WriteString(rr.rawx.ns)
	bb.WriteRune('\n')
	bb.WriteString("path ")
	bb.WriteString(rr.rawx.path)
	bb.WriteRune('\n')
	if rr.rawx.id != "" {
		bb.WriteString("service_id ")
		bb.WriteString(rr.rawx.id)
		bb.WriteRune('\n')
	}
	if rr.rawx.tlsUrl != "" {
		bb.WriteString("url_tls ")
		bb.WriteString(rr.rawx.tlsUrl)
		bb.WriteRune('\n')
	}

	rr.replyCode(http.StatusOK)
	rr.rep.Write(bb.Bytes())
}

func (rr *rawxRequest) serveInfo() {
	if err := rr.drain(); err != nil {
		rr.replyError("", err)
		return
	}

	var spent uint64
	switch rr.req.Method {
	case "GET", "HEAD":
		doGetInfo(rr)
		spent = IncrementStatReqInfo(rr)
	default:
		rr.replyCode(http.StatusMethodNotAllowed)
		spent = IncrementStatReqOther(rr)
	}
	if isVerbose() {
		LogHttp(AccessLogEvent{
			status:    rr.status,
			timeSpent: spent,
			bytesIn:   rr.bytesIn,
			bytesOut:  rr.bytesOut,
			method:    rr.req.Method,
			local:     rr.req.Host,
			peer:      rr.req.RemoteAddr,
			path:      rr.req.URL.Path,
			reqId:     rr.reqid,
			tls:       rr.req.TLS != nil,
		})
	}
}
