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
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"log/syslog"
)

type oioLogger interface {
	writeAccess(message string)
	writeInfo(message string)
	writeError(message string)
}

// Activate the extreme verbosity on the RAWX. This is has to be set at the
// startup of the service.
var logExtremeVerbosity = false

// The high severity (a.k.a. log level) that will be logged by the application.
var logDefaultSeverity = syslog.LOG_NOTICE

// When using
var logSeverity = logDefaultSeverity

// The RAWX doesn't daemonize, we can save one syscall for each access log line
// with this little variable caching the PID once for all.
var strPid = strconv.Itoa(os.Getpid())

// The singleton logger that will be used by all the coroutine
var logger oioLogger

func isVerbose() bool {
	return logExtremeVerbosity && severityAllowed(syslog.LOG_DEBUG)
}

func severityAllowed(severity syslog.Priority) bool {
	return severity <= logSeverity
}

func initVerbosity(severity syslog.Priority) {
	logDefaultSeverity = severity
	logSeverity = severity
}

func maximizeVerbosity() {
	logExtremeVerbosity = true
	logDefaultSeverity = syslog.LOG_DEBUG
	logSeverity = syslog.LOG_DEBUG
}

func increaseVerbosity() {
	if logSeverity < syslog.LOG_DEBUG {
		logSeverity = logSeverity + 1
	}
}

func resetVerbosity() {
	logSeverity = logDefaultSeverity
}

func getSeverity(priority syslog.Priority) (bool, string) {
	switch priority {
	case syslog.LOG_EMERG, syslog.LOG_CRIT, syslog.LOG_ERR:
		return true, "ERR"
	case syslog.LOG_WARNING:
		return false, "WRN"
	case syslog.LOG_NOTICE, syslog.LOG_INFO:
		return false, "INF"
	default:
		return false, "DBG"
	}
}

func writeLogFmt(pri syslog.Priority, format string, v ...interface{}) {
	if !severityAllowed(pri) {
		return
	}
	erroneous, severityName := getSeverity(pri)
	sb := strings.Builder{}
	sb.Grow(256)
	sb.WriteString(strPid)
	sb.WriteString(" log ")
	sb.WriteString(severityName)
	sb.WriteString(" - ")
	sb.WriteString(fmt.Sprintf(format, v...))
	if erroneous {
		logger.writeError(sb.String())
	} else {
		logger.writeInfo(sb.String())
	}
}

func LogFatal(format string, v ...interface{}) {
	writeLogFmt(syslog.LOG_ERR, format, v...)
	log.Fatalf(format, v...)
}

func LogError(format string, v ...interface{}) {
	writeLogFmt(syslog.LOG_ERR, format, v...)
}

func LogWarning(format string, v ...interface{}) {
	writeLogFmt(syslog.LOG_WARNING, format, v...)
}

func LogInfo(format string, v ...interface{}) {
	writeLogFmt(syslog.LOG_INFO, format, v...)
}

func LogDebug(format string, v ...interface{}) {
	writeLogFmt(syslog.LOG_DEBUG, format, v...)
}

type AccessLogEvent struct {
	status    int
	bytesIn   uint64
	bytesOut  uint64
	timeSpent uint64
	method    string
	local     string
	peer      string
	path      string
	reqId     string
}

func LogHttp(evt AccessLogEvent) {
	//url, peer, method string, status int, spent, bytes uint64, containerID, id, path string) {
	sb := strings.Builder{}
	sb.Grow(256)
	// Preamble
	sb.WriteString(strPid)
	sb.WriteString(" access INF - ")
	// Payload
	sb.WriteString(evt.local)
	sb.WriteRune(' ')
	sb.WriteString(evt.peer)
	sb.WriteRune(' ')
	sb.WriteString(evt.method)
	sb.WriteRune(' ')
	sb.WriteString(itoa(evt.status))
	sb.WriteRune(' ')
	sb.WriteString(utoa(evt.timeSpent))
	sb.WriteRune(' ')
	sb.WriteString(utoa(evt.bytesOut))
	sb.WriteRune(' ')
	sb.WriteString(utoa(evt.bytesIn))
	sb.WriteString(" - ")
	sb.WriteString(evt.reqId)
	sb.WriteRune(' ')
	sb.WriteString(evt.path)
	logger.writeAccess(sb.String())
}

type NoopLogger struct{}

func InitNoopLogger() {
	logger = &NoopLogger{}
}

func (*NoopLogger) writeAccess(string) {}
func (*NoopLogger) writeInfo(string)   {}
func (*NoopLogger) writeError(string)  {}

type SysLogger struct {
	syslogID     string
	loggerAccess *syslog.Writer
	loggerInfo   *syslog.Writer
	loggerError  *syslog.Writer
}

func InitSysLogger(syslogID string) {
	initVerbosity(syslog.LOG_INFO)
	var sysLogger SysLogger
	sysLogger.syslogID = syslogID
	sysLogger.loggerAccess, _ = syslog.New(syslog.LOG_LOCAL1|syslog.LOG_INFO, syslogID)
	sysLogger.loggerInfo, _ = syslog.New(syslog.LOG_LOCAL0|syslog.LOG_INFO, syslogID)
	sysLogger.loggerError, _ = syslog.New(syslog.LOG_LOCAL0|syslog.LOG_ERR, syslogID)
	logger = &sysLogger
}

func (l *SysLogger) writeAccess(m string) { l.loggerAccess.Info(m) }
func (l *SysLogger) writeInfo(m string)   { l.loggerInfo.Info(m) }
func (l *SysLogger) writeError(m string)  { l.loggerError.Err(m) }

type StderrLogger struct {
	logger *log.Logger
}

func InitStderrLogger() {
	initVerbosity(syslog.LOG_DEBUG)
	var stderrLogger StderrLogger
	stderrLogger.logger = log.New(os.Stderr, "", 0)
	stderrLogger.logger.SetFlags(log.Ldate | log.Lshortfile | log.Llongfile | log.Lmsgprefix)
	logger = &stderrLogger
}

func (l *StderrLogger) writeAll(m string) {
	now := time.Now()
	l.logger.Println(fmt.Sprintf("%v.%06d", now.Unix(), (now.UnixNano()/1000)%1000000), m)
}

func (l *StderrLogger) writeAccess(m string) { l.writeAll(m) }
func (l *StderrLogger) writeInfo(m string)   { l.writeAll(m) }
func (l *StderrLogger) writeError(m string)  { l.writeAll(m) }
