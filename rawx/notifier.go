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
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
	beanstalkNotifierPipeSize    = 4096
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
	notifier.queue = make(chan []byte, beanstalkNotifierPipeSize)
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
	err = beanstalkd.Use(notifier.tube)
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

	if !notifier.run {
		LogWarning("Can't send a event to %s using tube %s: closed",
			notifier.endpoint, notifier.tube)
		return
	}

	sb := bytes.Buffer{}
	sb.Grow(4096)
	addQuoted:= func (n string) {
		sb.WriteRune('"')
		sb.WriteString(n)
		sb.WriteRune('"')
	}
	addFieldRaw := func (k, v string) {
		sb.WriteRune(',')
		addQuoted(k)
		sb.WriteRune(':')
		sb.WriteString(v)
	}
	addFieldStr := func (k, v string) {
		addQuoted(k)
		sb.WriteRune(':')
		addQuoted(v)
	}
	add := func (k, v string) {
		if len(v) > 0 {
			sb.WriteRune(',')
			addFieldStr(k, v)
		}
	}
	addEscaped := func (k, v string) {
		if len(v) > 0 {
			sb.WriteRune(',')
			addQuoted(k)
			sb.WriteRune(':')
			sb.WriteRune('"')
			json.HTMLEscape(&sb, []byte(v))
			sb.WriteRune('"')
		}
	}

	sb.WriteRune('{')
	addFieldStr("event", eventType)
	addFieldRaw("when", strconv.FormatInt(time.Now().UnixNano() / 1000, 10))
	add("request_id", requestID)
	addFieldRaw("data", "{")
	addFieldStr("volume_id", notifier.rawx.url)
	add("volume_service_id", notifier.rawx.id)
	addEscaped("full_path", chunk.ContentFullpath)
	addEscaped("content_path", chunk.ContentPath)
	add("container_id", chunk.ContainerID)
	add("content_version", chunk.ContentVersion)
	add("content_id", chunk.ContentID)
	add("content_chunk_method", chunk.ContentChunkMethod)
	add("content_storage_policy", chunk.ContentStgPol)
	add("metachunk_hash", chunk.MetachunkHash)
	add("metachunk_size", chunk.MetachunkSize)
	add("chunk_id", chunk.ChunkID)
	add("chunk_position", chunk.ChunkPosition)
	add("chunk_hash", chunk.ChunkHash)
	add("chunk_size", chunk.ChunkSize)
	add("oio_version", chunk.OioVersion)
	sb.WriteString("}}")

	notifier.queue <- sb.Bytes()
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
	return nil, errors.New("Unexpected notification endpoint, only `beanstalk://...` is accepted")
}

func NotifyNew(notifier Notifier, requestID string, chunk *chunkInfo) {
	notifier.asyncNotify(eventTypeNewChunk, requestID, chunk)
}

func NotifyDel(notifier Notifier, requestID string, chunk *chunkInfo) {
	notifier.asyncNotify(eventTypeDelChunk, requestID, chunk)
}
