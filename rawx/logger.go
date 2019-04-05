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
	"log"
	"log/syslog"
	"os"
	"strings"
	"strconv"
)

type oioLogger interface {
	write(priority syslog.Priority, message string)
}

var logger oioLogger
var logDefaultSeverity = syslog.LOG_CRIT
var logSeverity = logDefaultSeverity

func severityAllowed(severity syslog.Priority) bool {
	return severity <= logSeverity
}

func initVerbosity(severity syslog.Priority) {
	logDefaultSeverity = severity
	logSeverity = severity
}

func increaseVerbosity() {
	if logSeverity < syslog.LOG_DEBUG {
		logSeverity = logSeverity + 1
	}
}

func resetVerbosity() {
	logSeverity = logDefaultSeverity
}

func getSeverity(priority syslog.Priority) (syslog.Priority, string) {
	switch priority {
	case syslog.LOG_CRIT:
		return syslog.LOG_ERR, "CRI"
	case syslog.LOG_ERR:
		return syslog.LOG_ERR, "ERR"
	case syslog.LOG_WARNING:
		return syslog.LOG_WARNING, "WRN"
	case syslog.LOG_NOTICE:
		return syslog.LOG_NOTICE, "NOT"
	case syslog.LOG_INFO:
		return syslog.LOG_INFO, "INF"
	default:
		return syslog.LOG_DEBUG, "DBG"
	}
}

func writeLogFmt(priority syslog.Priority, format string, v ...interface{}) {
	severity, severityName := getSeverity(priority)
	if !severityAllowed(severity) {
		return
	}

	sb := strings.Builder{}
	sb.Grow(256)
	sb.WriteString(strconv.Itoa(os.Getpid()))
	sb.WriteString(" log ")
	sb.WriteString(severityName)
	sb.WriteString(" - ")
	sb.WriteString(fmt.Sprintf(format, v...))
	logger.write(syslog.LOG_LOCAL0|severity, sb.String())
}

func LogError(format string, v ...interface{}) {
	writeLogFmt(syslog.LOG_ERR, format, v...)
}

func LogWarning(format string, v ...interface{}) {
	writeLogFmt(syslog.LOG_WARNING, format, v...)
}

func LogNotice(format string, v ...interface{}) {
	writeLogFmt(syslog.LOG_NOTICE, format, v...)
}

func LogInfo(format string, v ...interface{}) {
	writeLogFmt(syslog.LOG_INFO, format, v...)
}

func LogDebug(format string, v ...interface{}) {
	writeLogFmt(syslog.LOG_DEBUG, format, v...)
}

func LogIncoming(url, peer, method string, status int, spent, bytes uint64, id, path string) {
	sb := strings.Builder{}
	sb.Grow(128 + len(path))
	// Preamble
	sb.WriteString(strconv.Itoa(os.Getpid()))
	sb.WriteString(" access INF - ")
	// Payload
	sb.WriteString(url)
	sb.WriteRune(' ')
	sb.WriteString(peer)
	sb.WriteRune(' ')
	sb.WriteString(method)
	sb.WriteRune(' ')
	sb.WriteString(itoa(status))
	sb.WriteRune(' ')
	sb.WriteString(utoa(spent))
	sb.WriteRune(' ')
	sb.WriteString(utoa(bytes))
	sb.WriteRune(' ')
	sb.WriteString(id)
	sb.WriteRune(' ')
	sb.WriteString(path)
	logger.write(syslog.LOG_LOCAL1|syslog.LOG_INFO, sb.String())
}

func LogOutgoing(format string, v ...interface{}) {
	if !severityAllowed(syslog.LOG_DEBUG) {
		return
	}
	sb := strings.Builder{}
	sb.Grow(256)
	// Preamble
	sb.WriteString(strconv.Itoa(os.Getpid()))
	sb.WriteString(" out INF - ")
	// Payload
	sb.WriteString(fmt.Sprintf(format, v...))
	logger.write(syslog.LOG_LOCAL2|syslog.LOG_INFO, sb.String())
}

type NoopLogger struct {
}

func InitNoopLogger() {
	logger = new(NoopLogger)
}

func (log *NoopLogger) write(priority syslog.Priority, message string) {
}

type SysLogger struct {
	syslogID string
}

func InitSysLogger(syslogID string) {
	initVerbosity(syslog.LOG_INFO)
	sysLogger := new(SysLogger)
	sysLogger.syslogID = syslogID
	logger = sysLogger
}

func (log *SysLogger) write(priority syslog.Priority, message string) {
	logWriter, err := syslog.New(priority, log.syslogID)
	if err != nil {
		return
	}
	logWriter.Write([]byte(message))
	logWriter.Close()
}

type StderrLogger struct {
	logger *log.Logger
}

func InitStderrLogger() {
	initVerbosity(syslog.LOG_DEBUG)
	stderrLogger := new(StderrLogger)
	stderrLogger.logger = log.New(os.Stderr, "", 0)
	logger = stderrLogger
}

func (log *StderrLogger) write(priority syslog.Priority, message string) {
	log.logger.Println(message)
}
