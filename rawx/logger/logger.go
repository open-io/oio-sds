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
	"log/syslog"
	"os"
)

type OioLogger interface {
	Close()
	WriteEvent(message string)
	WriteAccess(message string)
	WriteInfo(message string)
	WriteError(message string)
}

// Activate the extreme verbosity on the RAWX. This has to be set at the
// startup of the service.
var LogExtremeVerbosity = false

// The high severity (a.k.a. log level) that will be logged by the application.
var LogDefaultSeverity = syslog.LOG_NOTICE

// When using
var logSeverity = LogDefaultSeverity

// The RAWX doesn't daemonize, we can save one syscall for each access log line
// with this little variable caching the PID once for all.
var Pid = os.Getpid()

// The singleton logger that will be used by all the coroutine
var logger OioLogger

type LogTemplateInventory struct {
	Pid      int
	Severity string
	Message  string
}

type LogRequestTemplateInventory struct {
	Pid      int
	Severity string
	Local    string
	Peer     string
	Method   string
	ReqId    string
	Path     string
	TLS      bool
	Message  string
}

func writeLogFmt(pri syslog.Priority, format string, v ...interface{}) {
	if !IsSeverityAllowed(pri) {
		return
	}
	erroneous, severityName := GetSeverity(pri)

	var output bytes.Buffer
	if LogTemplate != nil {
		err := LogTemplate.Execute(&output, LogTemplateInventory{
			Pid:      Pid,
			Severity: severityName,
			Message:  fmt.Sprintf(format, v...),
		})

		if err != nil {
			log.Printf("Error while executing LogTemplate: %v", err)
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

func LogFatal(format string, v ...interface{}) {
	writeLogFmt(syslog.LOG_ERR, format, v...)
	log.Fatalf(format, v...)
}

func LogError(format string, v ...interface{})   { writeLogFmt(syslog.LOG_ERR, format, v...) }
func LogWarning(format string, v ...interface{}) { writeLogFmt(syslog.LOG_WARNING, format, v...) }
func LogInfo(format string, v ...interface{})    { writeLogFmt(syslog.LOG_INFO, format, v...) }
func LogDebug(format string, v ...interface{})   { writeLogFmt(syslog.LOG_DEBUG, format, v...) }

func WriteError(message string)  { logger.WriteError(message) }
func WriteInfo(message string)   { logger.WriteInfo(message) }
func WriteAccess(message string) { logger.WriteAccess(message) }

func Close() { logger.Close() }
