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
	"log"
	"log/syslog"

	"openio-sds/rawx/logger"
)

// writeFormattedRequestLog formats a request-linked message
// according to the format specified by the RequestLogFormat configuration
// parameter and sends it to the system logger.
func writeFormattedRequestLog(rr *rawxRequest, pri syslog.Priority, format string, v ...interface{}) {
	if !logger.IsSeverityAllowed(pri) {
		return
	}
	erroneous, severityName := logger.GetSeverity(pri)

	var output bytes.Buffer
	if logger.RequestLogTemplate != nil {
		var local string
		var peer string
		var method string
		var reqId string
		var path string
		var TLS bool
		if rr != nil {
			local = rr.req.Host
			peer = rr.req.RemoteAddr
			method = rr.req.Method
			reqId = rr.reqid
			path = rr.req.URL.Path
			TLS = rr.req.TLS != nil
		} else {
			local = ""
			peer = ""
			method = ""
			reqId = ""
			path = ""
			TLS = false
		}
		err := logger.RequestLogTemplate.Execute(&output, logger.LogRequestTemplateInventory{
			Pid:      logger.Pid,
			Severity: severityName,
			Local:    local,
			Peer:     peer,
			Method:   method,
			ReqId:    reqId,
			Path:     path,
			TLS:      TLS,
			Message:  fmt.Sprintf(format, v...),
		})

		if err != nil {
			log.Printf("Error while executing RequestLogTemplate: %v", err)
			return
		}
	} else {
		log.Printf(format, v...)
		return
	}

	if erroneous {
		logger.WriteError(output.String())
	} else {
		logger.WriteInfo(output.String())
	}
}

func LogRequestFatal(rr *rawxRequest, format string, v ...interface{}) {
	writeFormattedRequestLog(rr, syslog.LOG_ERR, format, v...)
	log.Fatalf(format, v...)
}

func LogRequestError(rr *rawxRequest, format string, v ...interface{}) {
	writeFormattedRequestLog(rr, syslog.LOG_ERR, format, v...)
}

func LogRequestWarning(rr *rawxRequest, format string, v ...interface{}) {
	writeFormattedRequestLog(rr, syslog.LOG_WARNING, format, v...)
}

func LogRequestInfo(rr *rawxRequest, format string, v ...interface{}) {
	writeFormattedRequestLog(rr, syslog.LOG_INFO, format, v...)
}

func LogRequestDebug(rr *rawxRequest, format string, v ...interface{}) {
	writeFormattedRequestLog(rr, syslog.LOG_DEBUG, format, v...)
}
