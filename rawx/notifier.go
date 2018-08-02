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
	NotifyNew(requestID string, chunk *chunkInfo, rawx *rawxService) error
	NotifyDel(requestID string, chunk *chunkInfo, rawx *rawxService) error
}

type BeanstalkNotifier struct {
	url  string
	tube string
}

const (
	EventTypeNewChunk = "storage.chunk.new"
	EventTypeDelChunk = "storage.chunk.deleted"
)

const (
	defaultPriority = 1 << 31
	defaultTTR      = 120
)

func MakeBeanstalkNotifier(url, tubename string) (*BeanstalkNotifier, error) {
	// TODO(adu) Use connection pool
	notifier := new(BeanstalkNotifier)
	notifier.url = url
	notifier.tube = tubename
	// TODO(adu) Check URL
	return notifier, nil
}

func (notifier *BeanstalkNotifier) notify(eventType, requestID string,
	chunk *chunkInfo, rawx *rawxService) error {
	conn, err := beanstalk.Dial("tcp", notifier.url)
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

func (notifier *BeanstalkNotifier) NotifyNew(requestID string,
	chunk *chunkInfo, rawx *rawxService) error {
	return notifier.notify(EventTypeNewChunk, requestID, chunk, rawx)
}

func (notifier *BeanstalkNotifier) NotifyDel(requestID string,
	chunk *chunkInfo, rawx *rawxService) error {
	return notifier.notify(EventTypeDelChunk, requestID, chunk, rawx)
}
