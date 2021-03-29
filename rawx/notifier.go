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
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"encoding/json"
	"errors"
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
	errExiting      = errors.New("RAWX exiting")
	errClogged      = errors.New("Beanstalkd clogged")
	alertThrottling = PeriodicThrottle{period: 1000000000}
)

func deadLetter(event []byte, err error) {
	if err != nil && alertThrottling.Ok() {
		LogError("Beanstalkd connection error: %v", err)
	}
	if len(event) > 0 {
		LogWarning("event %s", string(event))
	}
}

func (backend *beanstalkdBackend) push(event []byte) {
	cnxDeadline := time.Now().Add(1 * time.Second)

	// Lazy reconnection
	for backend.b == nil {
		b, err := DialBeanstalkd(backend.endpoint)
		if err != nil {
			if time.Now().After(cnxDeadline) {
				deadLetter(event, err)
				return
			} else {
				time.Sleep(time.Second)
			}
		} else {
			err = b.Use(beanstalkNotifierDefaultTube)
			if err != nil {
				b.Close()
			} else {
				backend.b = b
			}
		}
	}

	if backend.b == nil {
		panic("BUG")
	}

	_, err := backend.b.Put(event)
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
		out := new(beanstalkdBackend)
		out.endpoint = endpoint
		out.tube = beanstalkNotifierDefaultTube
		return out, nil
	}
	// TODO(adu): make a ZMQ Notifier
	// TODO(jfs): make a GRPC Notifier
	// TODO(jfs): make an HTTP Notifier
	return nil, errors.New("Unexpected notification endpoint, only `beanstalk://...` is accepted")
}

func MakeNotifier(config string, rawx *rawxService) (*notifier, error) {
	n := new(notifier)
	n.queue = make(chan []byte, notifierDefaultPipeSize)
	n.running = true
	n.url = rawx.url
	n.srvid = rawx.id

	workers := make([]notifierBackend, 0)
	if !strings.Contains(config, ";") {
		for i := 0; i < notifierSingleMultiplier; i++ {
			backend, err := makeSingleBackend(config)
			if err != nil {
				return nil, err
			} else {
				workers = append(workers, backend)
			}
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
	doWork := func(w notifierBackend, input <-chan []byte) {
		defer n.wg.Done()
		for event := range input {
			if n.running {
				w.push(event)
			} else {
				deadLetter(event, errExiting)
			}
		}
		w.close()
	}

	for _, w := range workers {
		go doWork(w, n.queue)
	}

	return n, nil
}

func (n *notifier) notifyNew(requestID string, chunk chunkInfo) {
	if notifAllowed {
		n.asyncNotify(eventTypeNewChunk, requestID, chunk)
	}
}

func (n *notifier) notifyDel(requestID string, chunk chunkInfo) {
	if notifAllowed {
		n.asyncNotify(eventTypeDelChunk, requestID, chunk)
	}
}

type EncodableEvent struct {
	EventType string       `json:"event"`
	When      int64        `json:"when"`
	RequestId string       `json:"request_id"`
	Data      EventPayload `json:"data"`
}

type EventPayload struct {
	VolumeId       string `json:"volume_id"`
	ServiceId      string `json:"volume_service_id"`
	FullPath       string `json:"full_path"`
	ContainerId    string `json:"container_id"`
	ContentPath    string `json:"content_path"`
	ContentVersion string `json:"content_version"`
	ContentId      string `json:"content_id"`
	StgPol         string `json:"content_storage_policy"`
	MetaChunkHash  string `json:"metachunk_hash"`
	MetaChunkSize  string `json:"metachunk_size"`
	ChunkId        string `json:"chunk_id"`
	ChunkMethod    string `json:"content_chunk_method"`
	ChunkPosition  string `json:"chunk_position"`
	ChunkHash      string `json:"chunk_hash"`
	ChunkSize      string `json:"chunk_size"`
	OioVersion     string `json:"oio_version"`
}

func (n *notifier) asyncNotify(eventType, requestID string, chunk chunkInfo) {
	sb := bytes.Buffer{}
	sb.Grow(2048)
	evt := EncodableEvent{
		EventType: eventType,
		When:      time.Now().UnixNano() / 1000,
		RequestId: requestID,
		Data: EventPayload{
			VolumeId:       n.url,
			ServiceId:      n.srvid,
			FullPath:       chunk.ContentFullpath,
			ContainerId:    chunk.ContainerID,
			ContentPath:    chunk.ContentPath,
			ContentVersion: chunk.ContentVersion,
			ContentId:      chunk.ContentID,
			StgPol:         chunk.ContentStgPol,
			MetaChunkHash:  chunk.MetachunkHash,
			MetaChunkSize:  chunk.MetachunkSize,
			ChunkId:        chunk.ChunkID,
			ChunkMethod:    chunk.ContentChunkMethod,
			ChunkPosition:  chunk.ChunkPosition,
			ChunkHash:      chunk.ChunkHash,
			ChunkSize:      chunk.ChunkSize,
			OioVersion:     chunk.OioVersion,
		},
	}

	if err := json.NewEncoder(&sb).Encode(&evt); err != nil {
		LogWarning("JSON encoding error: %v", err)
	} else {
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
}

func (n *notifier) stop() {
	n.running = false
	close(n.queue)
	n.wg.Wait()
}
