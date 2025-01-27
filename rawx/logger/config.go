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
	"log"
	"log/syslog"
	"strings"
	"text/template"

	"openio-sds/rawx/defs"
)

var AccessLogGet = defs.ConfigDefaultAccessLogGet
var AccessLogPut = defs.ConfigDefaultAccessLogPut
var AccessLogPost = defs.ConfigDefaultAccessLogPost
var AccessLogDel = defs.ConfigDefaultAccessLogDelete

const concurrencyFormat = "put:{{ .Concurrency.Put }} get:{{ .Concurrency.Get }} del:{{ .Concurrency.Del }}"

var LogFormat = "{{ .Pid }} log {{ .Severity }} - {{ .Message }}"
var RequestLogFormat = "{{ .Pid }} log {{ .Severity }} - {{ .Local }} {{ .Peer }} {{ .Method }} - {{ .ReqId }} {{ .Path }} http{{ if .TLS }}s{{ end }} - {{ .Message }}"
var AccessLogFormat = "{{ .Pid }} access INF - {{ .Local }} {{ .Peer }} {{ .Method }} {{ .Status }} {{ .TimeSpent }} {{ .BytesOut }} {{ .BytesIn }} - {{ .ReqId }} {{ .Path }} http{{ if .TLS }}s{{ end }} {{ .TTFB }} " + concurrencyFormat
var EventLogFormat = "event INF {{ .Topic }} {{ .Event }}"

var LogTemplate *template.Template = nil
var RequestLogTemplate *template.Template = nil
var AccessLogTemplate *template.Template = nil
var EventLogTemplate *template.Template = nil

func InitLogTemplates() error {
	var err error
	log_funcs := template.FuncMap{
		"div1k": func(a uint64) float64 {
			return float64(a) / 1000.0
		},
		"div1M": func(a uint64) float64 {
			return float64(a) / 1000000.0
		},
	}
	LogTemplate, err = template.New("LogTemplate").Funcs(log_funcs).Parse(LogFormat)
	if err != nil {
		return err
	}
	RequestLogTemplate, err = template.New("RequestLogTemplate").Funcs(log_funcs).Parse(RequestLogFormat)
	if err != nil {
		return err
	}
	AccessLogTemplate, err = template.New("AccessLogTemplate").Funcs(log_funcs).Parse(AccessLogFormat)
	if err != nil {
		return err
	}
	EventLogTemplate, err = template.New("eventLogTemplate").Funcs(log_funcs).Parse(EventLogFormat)
	return err
}

func InitVerbosity(severity syslog.Priority) {
	LogDefaultSeverity = severity
	logSeverity = severity
}

func MaximizeVerbosity() {
	LogExtremeVerbosity = true
	LogDefaultSeverity = syslog.LOG_DEBUG
	logSeverity = syslog.LOG_DEBUG
}

func IncreaseVerbosity() {
	if logSeverity < syslog.LOG_DEBUG {
		logSeverity = logSeverity + 1
	}
}

func ResetVerbosity() {
	logSeverity = LogDefaultSeverity
}

func LogLevelToSeverity(level string) syslog.Priority {
	switch strings.ToLower(level) {
	case "emerg", "emergency":
		return syslog.LOG_EMERG
	case "alert":
		return syslog.LOG_ALERT
	case "crit", "critical":
		return syslog.LOG_CRIT
	case "err", "error":
		return syslog.LOG_ERR
	case "warn", "warning":
		return syslog.LOG_WARNING
	case "notice":
		return syslog.LOG_NOTICE
	case "info":
		return syslog.LOG_INFO
	case "debug":
		return syslog.LOG_DEBUG
	}
	log.Fatalf("Unknown log level '%s'", level)
	return syslog.LOG_EMERG
}

func IsVerbose() bool {
	return LogExtremeVerbosity && IsSeverityAllowed(syslog.LOG_DEBUG)
}

func IsSeverityAllowed(severity syslog.Priority) bool {
	return severity <= logSeverity
}

func GetSeverity(priority syslog.Priority) (bool, string) {
	switch priority {
	case syslog.LOG_EMERG, syslog.LOG_ALERT, syslog.LOG_CRIT, syslog.LOG_ERR:
		return true, "ERR"
	case syslog.LOG_WARNING:
		return false, "WRN"
	case syslog.LOG_NOTICE, syslog.LOG_INFO:
		return false, "INF"
	default:
		return false, "DBG"
	}
}
