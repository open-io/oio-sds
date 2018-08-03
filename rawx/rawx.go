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
	rawx       *rawxService
	req        *http.Request
	rep        http.ResponseWriter
	stats_hits int
	stats_time int
	reqid      string

	chunkID string
	chunk   chunkInfo

	// for the reply's purpose
	status    int
	bytes_out uint64
}

func (self *rawxRequest) replyCode(code int) {
	self.status = code
	self.rep.WriteHeader(self.status)
}

func (self *rawxRequest) replyError(err error) {
	if os.IsExist(err) {
		self.replyCode(http.StatusConflict)
	} else if os.IsPermission(err) {
		self.replyCode(http.StatusForbidden)
	} else if os.IsNotExist(err) {
		self.replyCode(http.StatusNotFound)
	} else {
		setError(self.rep, err)
		if err == os.ErrInvalid {
			self.replyCode(http.StatusBadRequest)
		} else {
			switch err {
			case ErrInvalidChunkID:
				self.replyCode(http.StatusBadRequest)
			case ErrMissingHeader:
				self.replyCode(http.StatusBadRequest)
			case ErrInvalidHeader:
				self.replyCode(http.StatusBadRequest)
			case ErrInvalidRange:
				self.replyCode(http.StatusRequestedRangeNotSatisfiable)
			default:
				self.replyCode(http.StatusInternalServerError)
			}
		}
	}
}

func (self *rawxService) ServeHTTP(rep http.ResponseWriter, req *http.Request) {
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
		rawx:       self,
		req:        req,
		rep:        rep,
		stats_time: TimeOther,
		stats_hits: HitsOther,
		reqid:      reqid,
	}

	if len(req.Host) > 0 && (req.Host != self.id && req.Host != self.url) {
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
	counters.Increment(rawxreq.stats_hits)
	counters.Add(rawxreq.stats_time, spent)
	counters.Increment(HitsTotal)
	counters.Add(TimeTotal, spent)

	trace := fmt.Sprintf(
		"%d - INF %s %s %s %d %d %d %s %s",
		os.Getpid(), self.url, req.RemoteAddr, req.Method,
		rawxreq.status, spent, rawxreq.bytes_out,
		rawxreq.reqid, req.URL.Path)
	logger_access.Print(trace)
}
