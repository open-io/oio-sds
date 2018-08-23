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
)

func doGetInfo(rr *rawxRequest) {
	rr.replyCode(http.StatusOK)
	rr.rep.Write([]byte(fmt.Sprintf("namespace %s\n", rr.rawx.ns)))
	rr.rep.Write([]byte(fmt.Sprintf("path %s\n", rr.rawx.path)))
	if rr.rawx.id != "" {
		rr.rep.Write([]byte(fmt.Sprintf("service_id %s\n", rr.rawx.id)))
	}
}

func (rr *rawxRequest) serveInfo(rep http.ResponseWriter, req *http.Request) {
	switch req.Method {
	case "GET":
		doGetInfo(rr)
		IncrementStatReqInfo(rr)
	default:
		rr.replyCode(http.StatusMethodNotAllowed)
		IncrementStatReqOther(rr)
	}
}
