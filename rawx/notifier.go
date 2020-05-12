// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
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

// Tells if the current RAWX service may emit notifications
var notifAllowed = configDefaultEvents

type notifier struct {
	queue   chan []byte
	wg      sync.WaitGroup
	running bool
	url     string
	srvid   string
}

type notifierBackend interface {
	push([]byte)
	close()
}

type beanstalkdBackend struct {
	b        *beanstalkClient
	endpoint string
	tube     string
}

var (
	errExiting = errors.New("RAWX exiting")
	errClogged = errors.New("Beanstalkd clogged")
	alertThrottling = PeriodicThrottle{period: 1000000000}
)

func deadLetter(event []byte, err error) {
	if err != nil && alertThrottling.Ok() {
		LogError("Beanstalkd connection error: %v", err)
	}
	LogWarning("event %s", string(event))
}

func (backend *beanstalkdBackend) push(event []byte) {
	var err error
	cnxDeadline := time.Now().Add(1 * time.Second)

	// Lazy reconnection
	for backend.b == nil {
		backend.b, err = DialBeanstalkd(backend.endpoint)
		if err != nil {
			if time.Now().After(cnxDeadline) {
				deadLetter(event, err)
				return
			} else {
				time.Sleep(time.Second)
			}
		} else {
			err = backend.b.Use(beanstalkNotifierDefaultTube)
			if err != nil {
				backend.close()
			}
		}
	}

	_, err = backend.b.Put(event)
	if err != nil {
		backend.close()
		deadLetter(event, err)
	}
}

func (backend *beanstalkdBackend) close() {
	if backend.b != nil {
		backend.b.Close()
		backend.b = nil
	}
}

func makeSingleBackend(config string) (notifierBackend, error) {
	if endpoint, ok := hasPrefix(config, "beanstalk://"); ok {
		return &beanstalkdBackend{
			endpoint: endpoint,
			tube:     beanstalkNotifierDefaultTube,
		}, nil
	}
	// TODO(adu): make a ZMQ Notifier
	// TODO(jfs): make a GRPC Notifier
	// TODO(jfs): make an HTTP Notifier
	return nil, errors.New("Unexpected notification endpoint, only `beanstalk://...` is accepted")
}

func MakeNotifier(config string, rawx *rawxService) (*notifier, error) {
	var n notifier
	n.queue = make(chan []byte, notifierDefaultPipeSize)
	n.running = true
	n.url = rawx.url
	n.srvid = rawx.id

	workers := make([]notifierBackend, 0)
	if strings.Contains(config, ";") {
		for i := 0; i < notifierSingleMultiplier; i++ {
			backend, err := makeSingleBackend(config)
			if err != nil {
				return nil, err
			}
			workers = append(workers, backend)
		}
	} else {
		for _, conf := range strings.Split(config, ";") {
			for i := 0; i < notifierMultipleMultiplier; i++ {
				backend, err := makeSingleBackend(conf)
				if err != nil {
					return nil, err
				} else {
					workers = append(workers, backend)
				}
			}
		}
	}

	n.wg.Add(len(workers))
	for _, w := range workers {
		go func(input <-chan []byte) {
			defer n.wg.Done()
			for event := range input {
				if n.running {
					w.push(event)
				} else {
					deadLetter(event, errExiting)
				}
			}
			w.close()
		}(n.queue)
	}

	return &n, nil
}

func (n notifier) notifyNew(requestID string, chunk chunkInfo) {
	if notifAllowed {
		n.asyncNotify(eventTypeNewChunk, requestID, chunk)
	}
}

func (n notifier) notifyDel(requestID string, chunk chunkInfo) {
	if notifAllowed {
		n.asyncNotify(eventTypeDelChunk, requestID, chunk)
	}
}

func (n notifier) asyncNotify(eventType, requestID string, chunk chunkInfo) {
	sb := bytes.Buffer{}
	sb.Grow(2048)
	addQuoted := func(n string) {
		sb.WriteRune('"')
		sb.WriteString(n)
		sb.WriteRune('"')
	}
	addFieldRaw := func(k, v string) {
		sb.WriteRune(',')
		addQuoted(k)
		sb.WriteRune(':')
		sb.WriteString(v)
	}
	addFieldStr := func(k, v string) {
		addQuoted(k)
		sb.WriteRune(':')
		addQuoted(v)
	}
	add := func(k, v string) {
		if len(v) > 0 {
			sb.WriteRune(',')
			addFieldStr(k, v)
		}
	}
	addEscaped := func(k, v string) {
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
	addFieldRaw("when", strconv.FormatInt(time.Now().UnixNano()/1000, 10))
	add("request_id", requestID)
	addFieldRaw("data", "{")
	addFieldStr("volume_id", n.url)
	add("volume_service_id", n.srvid)
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

	event := sb.Bytes()
	if !n.running {
		deadLetter(event, errExiting)
	} else {
		select {
		case n.queue <- event:
		default:
			deadLetter(event, errClogged)
		}
	}
}

func (n *notifier) stop() {
	n.running = false
	close(n.queue)
	n.wg.Wait()
}
