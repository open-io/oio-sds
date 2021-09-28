// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2020-2021 OVH SAS
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
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

type rawxService struct {
	ns           string
	url          string
	tlsUrl       string
	path         string
	id           string
	repo         chunkRepository
	notifier     *notifier
	bufferSize   int
	checksumMode int
	compression  string

	uploadBufferPool bufferPool

	// for IO errors
	lastIOError   time.Time
	lastIOSuccess time.Time
	lastIOMsg     string
	lastIOReport  time.Time
}

type rawxRequest struct {
	rawx      *rawxService
	req       *http.Request
	rep       http.ResponseWriter
	reqid     string
	startTime time.Time
	TTFB      time.Duration

	chunkID string
	chunk   chunkInfo

	// for the reply's purpose
	status   int
	bytesIn  uint64
	bytesOut uint64
}

func (rr *rawxRequest) drain() error {
	if _, err := io.Copy(ioutil.Discard, rr.req.Body); err != nil {
		rr.req.Close = true
		return err
	} else {
		return nil
	}
}

func (rr *rawxRequest) replyCode(code int) {
	rr.status = code
	rr.rep.WriteHeader(rr.status)
}

func (rr *rawxRequest) replyError(action string, err error) {
	if os.IsExist(err) {
		rr.replyCode(http.StatusConflict)
	} else if os.IsPermission(err) {
		rr.replyCode(http.StatusForbidden)
	} else if os.IsNotExist(err) {
		rr.replyCode(http.StatusNotFound)
	} else {
		// A strong error occured, we tend to close the connection
		// whatever the client has sent in the request, in terms of
		// connection management.
		rr.req.Close = true

		if len(action) != 0 {
			LogError(msgErrorAction(action, rr.reqid, err))
		}

		// Also, we debug what happened in the reply headers
		// TODO(jfs): This is a job for a distributed tracing framework
		if logExtremeVerbosity {
			rr.rep.Header().Set(HeaderNameError, err.Error())
		}

		// Prepare the most adapted reply status.
		if err == os.ErrInvalid {
			rr.replyCode(http.StatusBadRequest)
		} else {
			switch err {
			case errInvalidChunkID, errMissingHeader, errInvalidHeader:
				rr.replyCode(http.StatusBadRequest)
			case errInvalidRange:
				rr.replyCode(http.StatusRequestedRangeNotSatisfiable)
			default:
				rr.replyCode(http.StatusInternalServerError)
			}
		}
	}
}

func (rawx *rawxService) getURL() string {
	if rawx.id == "" {
		return rawx.url
	}
	return rawx.id
}

func (rawx *rawxService) isIOok() bool {
	// Never touched -> OK
	if rawx.lastIOError.Equal(time.Time{}) &&
		rawx.lastIOSuccess.Equal(time.Time{}) {
		return true
	}

	// The most recent activity is an error -> KO
	if rawx.lastIOError.After(rawx.lastIOSuccess) {
		return false
	}

	// Check the probe thread was not stalled
	now := time.Now()
	oneMinuteBefore := now.Add(-time.Minute)
	ok := rawx.lastIOSuccess.After(oneMinuteBefore)
	if !ok {
		// If this function is called often, only report once per minute
		if now.After(rawx.lastIOReport.Add(time.Minute)) {
			rawx.lastIOReport = now
			LogWarning("IO error checker stalled for %d minutes",
				now.Sub(rawx.lastIOSuccess)/time.Minute)
		}
	}

	return ok
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
		if len(rawxreq.reqid) > HeaderLenOioReqId {
			rawxreq.reqid = rawxreq.reqid[0:HeaderLenOioReqId]
		}
		rep.Header().Set(HeaderNameOioReqId, rawxreq.reqid)
	} else {
		// patch the reqid for pretty access log
		rawxreq.reqid = "-"
	}

	if len(req.Host) > 0 && (req.Host != rawx.id && req.Host != rawx.url && req.Host != rawx.tlsUrl) {
		rawxreq.replyCode(http.StatusTeapot)
	} else if !rawx.isIOok() {
		rawxreq.replyCode(http.StatusServiceUnavailable)
	} else {
		for _dslash(req.URL.Path) {
			req.URL.Path = req.URL.Path[1:]
		}
		switch req.URL.Path {
		case "/info":
			rawxreq.serveInfo()
		case "/stat":
			rawxreq.serveStat()
		default:
			rawxreq.serveChunk()
		}
	}
}
