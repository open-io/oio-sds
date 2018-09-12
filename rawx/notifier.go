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
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

type eventData struct {
	VolumeAddr string `json:"volume_id,omitempty"`
	VolumeID   string `json:"volume_service_id,omitempty"`
	chunkInfo
}

type eventInfo struct {
	EventType string    `json:"event"`
	When      int64     `json:"when"`
	URL       *string   `json:"url"`
	RequestID string    `json:"request_id,omitempty"`
	Data      eventData `json:"data"`
}

type Notifier interface {
	Start()
	Stop()
	asyncNotify(eventType, requestID string, chunk *chunkInfo)
}

const (
	eventTypeNewChunk = "storage.chunk.new"
	eventTypeDelChunk = "storage.chunk.deleted"
)

const (
	beanstalkNotifierDefaultTube = "oio"
)

var (
	ErrNoNotiifer = errors.New("No notifier")
)

type beanstalkNotifier struct {
	rawx       *rawxService
	run        bool
	wg         sync.WaitGroup
	queue      chan []byte
	endpoint   string
	tube       string
	beanstalkd *Beanstalkd
}

func makeBeanstalkNotifier(endpoint string,
	rawx *rawxService) (*beanstalkNotifier, error) {
	// TODO(adu) Use connection pool
	notifier := new(beanstalkNotifier)
	notifier.rawx = rawx
	notifier.run = false
	notifier.queue = make(chan []byte)
	notifier.endpoint = endpoint
	notifier.tube = beanstalkNotifierDefaultTube
	// TODO(adu) Check endpoint
	notifier.beanstalkd = nil
	return notifier, nil
}

func (notifier *beanstalkNotifier) Start() {
	notifier.wg.Add(1)
	go func() {
		defer notifier.wg.Done()
		for eventJSON := range notifier.queue {
			notifier.syncNotify(eventJSON)
		}
	}()
	notifier.run = true
}

func (notifier *beanstalkNotifier) Stop() {
	notifier.run = false
	close(notifier.queue)
	notifier.wg.Wait()
	notifier.closeBeanstalkd()
}

func (notifier *beanstalkNotifier) connectBeanstalkd() error {
	if notifier.beanstalkd != nil {
		return nil
	}
	LogDebug("Connecting to %s using tube %s", notifier.endpoint, notifier.tube)
	beanstalkd, err := DialBeanstalkd(notifier.endpoint)
	if err != nil {
		return err
	}
	notifier.beanstalkd = beanstalkd
	return nil
}

func (notifier *beanstalkNotifier) closeBeanstalkd() {
	notifier.beanstalkd.Close()
	notifier.beanstalkd = nil
}

func (notifier *beanstalkNotifier) syncNotify(eventJSON []byte) {
	err := notifier.connectBeanstalkd()
	if err != nil {
		LogWarning("ERROR to connect to %s using tube %s: %s",
			notifier.endpoint, notifier.tube, err)
		return
	}
	_, err = notifier.beanstalkd.Put(eventJSON)
	if err != nil {
		LogWarning("ERROR to notify to %s using tube %s: %s",
			notifier.endpoint, notifier.tube, err)
		notifier.closeBeanstalkd()
		return
	}
}

func (notifier *beanstalkNotifier) asyncNotify(eventType, requestID string,
	chunk *chunkInfo) {
	eventJSON, _ := json.Marshal(eventInfo{
		EventType: eventType,
		When:      time.Now().UnixNano() / 1000,
		RequestID: requestID,
		Data: eventData{
			VolumeAddr: notifier.rawx.url,
			VolumeID:   notifier.rawx.id,
			chunkInfo:  *chunk,
		},
	})
	if !notifier.run {
		LogWarning("Can't send a event to %s using tube %s: closed",
			notifier.endpoint, notifier.tube)
		return
	}
	notifier.queue <- eventJSON
}

type multiNotifier struct {
	notifiers []Notifier
	index     int
}

func makeMultiNotifier(config string, rawx *rawxService) (*multiNotifier, error) {
	notifier := new(multiNotifier)
	confs := strings.Split(config, ";")
	for _, conf := range confs {
		notif, err := MakeNotifier(conf, rawx)
		if err != nil {
			return nil, err
		}
		notifier.notifiers = append(notifier.notifiers, notif)
	}
	return notifier, nil
}

func (notifier *multiNotifier) Start() {
	for _, notif := range notifier.notifiers {
		notif.Start()
	}
}

func (notifier *multiNotifier) Stop() {
	for _, notif := range notifier.notifiers {
		notif.Stop()
	}
}

func (notifier *multiNotifier) asyncNotify(eventType, requestID string,
	chunk *chunkInfo) {
	notif := notifier.notifiers[notifier.index]
	// Round-robin
	notifier.index = (notifier.index + 1) % len(notifier.notifiers)
	notif.asyncNotify(eventType, requestID, chunk)
}

func hasPrefix(s, prefix string) (string, bool) {
	if strings.HasPrefix(s, prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

func MakeNotifier(config string, rawx *rawxService) (Notifier, error) {
	if strings.Contains(config, ";") {
		return makeMultiNotifier(config, rawx)
	}

	if endpoint, ok := hasPrefix(config, "beanstalk://"); ok {
		return makeBeanstalkNotifier(endpoint, rawx)
	}
	// TODO(adu) makeZMQNotifier
	return nil, ErrNoNotiifer
}

func NotifyNew(notifier Notifier, requestID string, chunk *chunkInfo) {
	notifier.asyncNotify(eventTypeNewChunk, requestID, chunk)
}

func NotifyDel(notifier Notifier, requestID string, chunk *chunkInfo) {
	notifier.asyncNotify(eventTypeDelChunk, requestID, chunk)
}
