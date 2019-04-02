// OpenIO SDS Go rawx
// Copyright (C) 2015-2019 OpenIO SAS
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
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	HeaderNameOioReqId = "X-oio-req-id"
	HeaderNameTransId  = "X-trans-id"
	HeaderNameError    = "X-Error"
)

func setErrorString(rep http.ResponseWriter, s string) {
	rep.Header().Set(HeaderNameError, s)
}

func setError(rep http.ResponseWriter, e error) {
	setErrorString(rep, e.Error())
}

type rawxService struct {
	ns       string
	url      string
	path     string
	id       string
	repo     repository
	compress bool
	notifier Notifier
}

type rawxRequest struct {
	rawx      *rawxService
	req       *http.Request
	rep       http.ResponseWriter
	reqid     string
	startTime time.Time

	chunkID string
	chunk   chunkInfo

	// for the reply's purpose
	status   int
	bytesIn  uint64
	bytesOut uint64
}

func (rr *rawxRequest) replyCode(code int) {
	rr.status = code
	rr.rep.WriteHeader(rr.status)
}

func (rr *rawxRequest) getSpent() uint64 {
	return uint64(time.Since(rr.startTime).Nanoseconds() / 1000)
}

func (rr *rawxRequest) replyError(err error) {
	if os.IsExist(err) {
		rr.replyCode(http.StatusConflict)
	} else if os.IsPermission(err) {
		rr.replyCode(http.StatusForbidden)
	} else if os.IsNotExist(err) {
		rr.replyCode(http.StatusNotFound)
	} else {
		setError(rr.rep, err)
		if err == os.ErrInvalid {
			rr.replyCode(http.StatusBadRequest)
		} else {
			switch err {
			case errInvalidChunkID:
				rr.replyCode(http.StatusBadRequest)
			case errMissingHeader:
				rr.replyCode(http.StatusBadRequest)
			case errInvalidHeader:
				rr.replyCode(http.StatusBadRequest)
			case errInvalidRange:
				rr.replyCode(http.StatusRequestedRangeNotSatisfiable)
			default:
				rr.replyCode(http.StatusInternalServerError)
			}
		}
	}
}

func (rawx *rawxService) ServeHTTP(rep http.ResponseWriter, req *http.Request) {
	rawxreq := rawxRequest{
		rawx:      rawx,
		req:       req,
		rep:       rep,
		reqid:     "",
		startTime: time.Now(),
	}

	// Extract some common headers
	rawxreq.reqid = req.Header.Get(HeaderNameOioReqId)
	if len(rawxreq.reqid) <= 0 {
		rawxreq.reqid = req.Header.Get(HeaderNameTransId)
	}
	if len(rawxreq.reqid) > 0 {
		rep.Header().Set(HeaderNameTransId, rawxreq.reqid)
	} else {
		// patch the reqid for pretty access log
		rawxreq.reqid = "-"
	}

	if len(req.Host) > 0 && (req.Host != rawx.id && req.Host != rawx.url) {
		rawxreq.replyCode(http.StatusTeapot)
	} else {
		if strings.HasPrefix(req.URL.Path, "//") == true {
			req.URL.Path = req.URL.Path[1:]
		}
		switch req.URL.Path {
		case "/info":
			rawxreq.serveInfo(rep, req)
		case "/stat":
			rawxreq.serveStat(rep, req)
		default:
			rawxreq.serveChunk()
		}
	}
}
