// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2020-2024 OVH SAS
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
	"fmt"
	"os"
	"sync"
	"time"

	"openio-sds/rawx/defs"
	"openio-sds/rawx/logger"
	"openio-sds/rawx/utils"
)

type RawxProbe struct {
	latch sync.RWMutex

	lastIOError   time.Time
	lastIOSuccess time.Time
	lastIOReport  time.Time

	lastIOMsg string
}

func (rp *RawxProbe) GetLastIOMsg() string {
	rp.latch.RLock()
	defer rp.latch.RUnlock()

	return rp.lastIOMsg
}

func (rp *RawxProbe) OK() bool {
	rp.latch.RLock()
	defer rp.latch.RUnlock()

	// Never touched -> OK
	if rp.lastIOError.Equal(time.Time{}) &&
		rp.lastIOSuccess.Equal(time.Time{}) {
		return true
	}

	// The most recent activity is an error -> KO
	if rp.lastIOError.After(rp.lastIOSuccess) {
		return false
	}

	// Check the probe thread was not stalled
	now := time.Now()
	oneMinuteBefore := now.Add(-time.Minute)
	ok := rp.lastIOSuccess.After(oneMinuteBefore)
	if !ok {
		// If this function is called often, only report once per minute
		if now.After(rp.lastIOReport.Add(time.Minute)) {
			rp.lastIOReport = now
			logger.LogWarning("IO error checker stalled for %d minutes",
				now.Sub(rp.lastIOSuccess)/time.Minute)
		}
	}

	return ok
}

func (rp *RawxProbe) ProbeLoop(basedir string, tag string, finished chan bool) {
	for {
		for i := 0; i < 5; i++ {
			time.Sleep(time.Second)
			select {
			case <-finished:
				logger.LogInfo("Stop the probe to check the repository")
				return
			default:
			}
		}
		rp.probeOnce(basedir, tag, finished)
	}
}

func (rp *RawxProbe) probeOnce(basedir string, tag string, finished chan bool) {
	/* Try a directory creation */
	path := fmt.Sprintf("%s/probe-%s", basedir, utils.RandomString(16, defs.HexaCharacters))
	logger.LogDebug("Probing directory %s", path)
	err := os.Mkdir(path, 0755)
	os.Remove(path)
	if err != nil {
		msg := fmt.Sprintf("IO error on %s %s: %v", tag, path, err)
		logger.LogWarning(msg)
		rp.notifyError(msg)
		return
	}

	/* Try a file creation */
	path = fmt.Sprintf("%s/probe-%s", basedir, utils.RandomString(16, defs.HexaCharacters))
	logger.LogDebug("Probing file %s", path)
	file, err := os.Create(path)
	file.Close()
	os.Remove(path)
	if err != nil {
		msg := fmt.Sprintf("IO error on %s %s: %v", tag, path, err)
		logger.LogWarning(msg)
		rp.notifyError(msg)
		return
	}

	rp.notifySuccess()
}

func (rp *RawxProbe) notifySuccess() {
	now := time.Now()

	rp.latch.Lock()
	defer rp.latch.Unlock()

	rp.lastIOSuccess = now
	rp.lastIOMsg = "n/a"
}

func (rp *RawxProbe) notifyError(msg string) {
	now := time.Now()

	rp.latch.Lock()
	defer rp.latch.Unlock()

	rp.lastIOError = now
	rp.lastIOMsg = msg
}
