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
	"log/syslog"
	"sync"

	"openio-sds/rawx/defs"
	"openio-sds/rawx/utils"
)

type SysLogger struct {
	queue         chan string
	wg            sync.WaitGroup
	running       bool
	syslogID      string
	alertThrottle utils.Throttle
	loggerAccess  *syslog.Writer
	loggerInfo    *syslog.Writer
	loggerError   *syslog.Writer
}

func InitSysLogger(syslogID string) {
	l := &SysLogger{}
	l.alertThrottle = utils.NewPeriodicThrottle(1000000000)
	l.queue = make(chan string, defs.ConfigDefaultAccessLogQueueLength)
	l.running = true
	l.syslogID = syslogID
	l.loggerAccess, _ = syslog.New(syslog.LOG_LOCAL1|syslog.LOG_INFO, syslogID)
	l.loggerInfo, _ = syslog.New(syslog.LOG_LOCAL0|syslog.LOG_INFO, syslogID)
	l.loggerError, _ = syslog.New(syslog.LOG_LOCAL0|syslog.LOG_ERR, syslogID)
	l.wg.Add(1)
	go func() {
		for evt := range l.queue {
			l.loggerAccess.Info(evt)
		}
		l.wg.Done()
	}()
	logger = l
}

func (l *SysLogger) WriteAccess(m string) {
	select {
	case l.queue <- m: // no-blocking call, everything is fine
	default:
		if l.alertThrottle.Ok() {
			LogWarning("syslog clogged")
		}
		// FIXME(jfs): Uncomment this upon an absolute necessity
		// l.queue <- m
	}
}

func (l *SysLogger) WriteInfo(m string)  { l.loggerInfo.Info(m) }
func (l *SysLogger) WriteError(m string) { l.loggerError.Err(m) }
func (l *SysLogger) WriteEvent(m string) { l.WriteAccess(m) }
func (l *SysLogger) Close() {
	l.running = false
	close(l.queue)
	l.wg.Wait()
}
