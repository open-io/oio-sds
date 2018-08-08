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
	"time"

	"github.com/kr/beanstalk"
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
	notify(eventType, requestID string, chunk *chunkInfo, rawx *rawxService) error
}

const (
	eventTypeNewChunk = "storage.chunk.new"
	eventTypeDelChunk = "storage.chunk.deleted"
)

const (
	defaultPriority = 1 << 31
	defaultTTR      = 120
)

const (
	beanstalkNotifierDefaultTube = "oio"
)

var (
	ErrNoNotiifer = errors.New("No notifier")
)

type beanstalkNotifier struct {
	endpoint string
	tube     string
}

func makeBeanstalkNotifier(endpoint string) (*beanstalkNotifier, error) {
	// TODO(adu) Use connection pool
	notifier := new(beanstalkNotifier)
	notifier.endpoint = endpoint
	notifier.tube = beanstalkNotifierDefaultTube
	// TODO(adu) Check endpoint
	return notifier, nil
}

func (notifier *beanstalkNotifier) notify(eventType, requestID string,
	chunk *chunkInfo, rawx *rawxService) error {
	conn, err := beanstalk.Dial("tcp", notifier.endpoint)
	if err != nil {
		return err
	}
	defer conn.Close()
	tube := beanstalk.Tube{conn, notifier.tube}

	eventJSON, _ := json.Marshal(eventInfo{
		EventType: eventType,
		When:      time.Now().UnixNano() / 1000,
		RequestID: requestID,
		Data: eventData{
			VolumeAddr: rawx.url,
			VolumeID:   rawx.id,
			chunkInfo:  *chunk,
		},
	})
	_, err = tube.Put(eventJSON, defaultPriority, 0, defaultTTR)
	return err
}

type multiNotifier struct {
	notifiers []Notifier
	index     int
}

func makeMultiNotifier(config string) (*multiNotifier, error) {
	notifier := new(multiNotifier)
	confs := strings.Split(config, ";")
	for _, conf := range confs {
		notif, err := MakeNotifier(conf)
		if err != nil {
			return nil, err
		}
		notifier.notifiers = append(notifier.notifiers, notif)
	}
	return notifier, nil
}

func (notifier *multiNotifier) notify(eventType, requestID string,
	chunk *chunkInfo, rawx *rawxService) error {
	notif := notifier.notifiers[notifier.index]
	// Round-robin
	notifier.index = (notifier.index + 1) % len(notifier.notifiers)
	return notif.notify(eventType, requestID, chunk, rawx)
}

func hasPrefix(s, prefix string) (string, bool) {
	if strings.HasPrefix(s, prefix) {
		return s[len(prefix):], true
	}
	return "", false
}

func MakeNotifier(config string) (Notifier, error) {
	if strings.Contains(config, ";") {
		return makeMultiNotifier(config)
	}

	if endpoint, ok := hasPrefix(config, "beanstalk://"); ok {
		return makeBeanstalkNotifier(endpoint)
	}
	// TODO(adu) makeZMQNotifier
	return nil, ErrNoNotiifer
}

func NotifyNew(notifier Notifier, requestID string,
	chunk *chunkInfo, rawx *rawxService) error {
	return notifier.notify(eventTypeNewChunk, requestID, chunk, rawx)
}

func NotifyDel(notifier Notifier, requestID string,
	chunk *chunkInfo, rawx *rawxService) error {
	return notifier.notify(eventTypeDelChunk, requestID, chunk, rawx)
}
