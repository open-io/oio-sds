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
	"os"
	"path/filepath"
	"time"
)

func setErrorString(rep http.ResponseWriter, s string) {
	rep.Header().Set("X-Error", s)
}

func setError(rep http.ResponseWriter, e error) {
	setErrorString(rep, e.Error())
}

type rawxService struct {
	ns       string
	url      string
	id       string
	repo     Repository
	compress bool
	notifier Notifier
}

type rawxRequest struct {
	rawx      *rawxService
	req       *http.Request
	rep       http.ResponseWriter
	statsHits int
	statsTime int
	reqid     string

	chunkID string
	chunk   chunkInfo

	// for the reply's purpose
	status   int
	bytesOut uint64
}

func (rr *rawxRequest) replyCode(code int) {
	rr.status = code
	rr.rep.WriteHeader(rr.status)
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
			case ErrInvalidChunkID:
				rr.replyCode(http.StatusBadRequest)
			case ErrMissingHeader:
				rr.replyCode(http.StatusBadRequest)
			case ErrInvalidHeader:
				rr.replyCode(http.StatusBadRequest)
			case ErrInvalidRange:
				rr.replyCode(http.StatusRequestedRangeNotSatisfiable)
			default:
				rr.replyCode(http.StatusInternalServerError)
			}
		}
	}
}

func (rawx *rawxService) ServeHTTP(rep http.ResponseWriter, req *http.Request) {
	pre := time.Now()

	// Sanitizes the Path, trim repeated separators, etc
	req.URL.Path = filepath.Clean(req.URL.Path)

	// Extract some common headers
	reqid := req.Header.Get("X-oio-reqid")
	if len(reqid) <= 0 {
		reqid = req.Header.Get("X-trans-id")
	}
	if len(reqid) > 0 {
		rep.Header().Set("X-trans-id", reqid)
	} else {
		// patch the reqid for pretty access log
		reqid = "-"
	}

	// Forward to the request method
	rawxreq := rawxRequest{
		rawx:      rawx,
		req:       req,
		rep:       rep,
		statsTime: TimeOther,
		statsHits: HitsOther,
		reqid:     reqid,
	}

	if len(req.Host) > 0 && (req.Host != rawx.id && req.Host != rawx.url) {
		rawxreq.replyCode(http.StatusTeapot)
	} else {
		if req.URL.Path == "/info" || req.URL.Path == "/stat" {
			rawxreq.serveStat(rep, req)
		} else {
			rawxreq.serveChunk(rep, req)
		}
	}

	spent := uint64(time.Since(pre).Nanoseconds() / 1000)

	// Increment counters and log the request
	counters.Increment(rawxreq.statsHits)
	counters.Add(rawxreq.statsTime, spent)
	counters.Increment(HitsTotal)
	counters.Add(TimeTotal, spent)

	trace := fmt.Sprintf(
		"%d - INF %s %s %s %d %d %d %s %s",
		os.Getpid(), rawx.url, req.RemoteAddr, req.Method,
		rawxreq.status, spent, rawxreq.bytesOut,
		rawxreq.reqid, req.URL.Path)
	loggerAccess.Print(trace)
}
