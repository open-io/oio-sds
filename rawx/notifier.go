// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2021-2023 OVH SAS
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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/confluentinc/confluent-kafka-go/kafka"
	amqp "github.com/rabbitmq/amqp091-go"
)

// Tells if the current RAWX service may emit notifications
var notifAllowed = configDefaultEvents

// Represents a chunk event with a routing key.
// routingKey will not be used when sending to Beanstalkd,
// but will be with AMQP. The routing key will be the event type, basically.
type routedEvent struct {
	event      []byte
	routingKey string
}

type notifier struct {
	queue   chan routedEvent
	wg      sync.WaitGroup
	running bool
	url     string
	srvid   string
}

type notifierBackend interface {
	push(event []byte, routingKey string)
	close()
}

type beanstalkdBackend struct {
	b             *beanstalkClient
	endpoint      string
	tube          string
	conn_attempts int
	conn_timeout  time.Duration
}

type amqpBackend struct {
	cnx           *amqp.Connection
	channel       *amqp.Channel
	urls          []string
	urlId         int
	exchange      string
	conn_attempts int
	conn_timeout  time.Duration
	send_timeout  time.Duration
}

type kafkaBackend struct {
	endpoint string
	topic    string
	producer *kafka.Producer
}

var (
	errExiting      = errors.New("RAWX exiting")
	errClogged      = errors.New("Beanstalkd clogged")
	alertThrottling = PeriodicThrottle{period: 1000000000}
)

func deadLetter(event []byte, err error) {
	if err != nil && alertThrottling.Ok() {
		LogError("Event broker connection error: %v", err)
	}
	if len(event) > 0 {
		LogWarning("event %s", string(event))
	}
}

func (backend *beanstalkdBackend) push(event []byte, routingKey string) {
	cnxDeadline := time.Now().Add(
		time.Duration(backend.conn_attempts) * backend.conn_timeout)

	// Lazy reconnection
	for backend.b == nil {
		b, err := DialBeanstalkd(backend.endpoint, backend.conn_timeout)
		if err != nil {
			if time.Now().After(cnxDeadline) {
				deadLetter(event, err)
				return
			} else {
				time.Sleep(backend.conn_timeout / 2)
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
		panic("BUG: connection loop exited without creating backend")
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

// connect connects to one of the configured AMQP endpoints and opens a
// channel. If the connection is already established, do nothing. If the
// current endpoint is not available, try the next one, in a round-robin
// fashion.
func (backend *amqpBackend) connect() error {
	// Deadline for the connection attempts, not TCP connection timeout.
	cnxDeadline := time.Now().Add(
		time.Duration(backend.conn_attempts) * backend.conn_timeout)

	for backend.cnx == nil {
		// backend.urls contains credentials, must be filtered before logging,
		// hence the logging of urlId.
		LogDebug("Connecting to event broker #%d", backend.urlId)
		cnx, err := amqp.DialConfig(backend.urls[backend.urlId], amqp.Config{
			Dial: func(network, addr string) (net.Conn, error) {
				return net.DialTimeout(network, addr, backend.conn_timeout)
			},
			// Setting this low (the default is 10s) will help us identify
			// outages when the activity is low.
			Heartbeat: 2 * time.Second,
		})
		backend.urlId = (backend.urlId + 1) % len(backend.urls)
		if err != nil {
			if time.Now().After(cnxDeadline) {
				return err
			} else {
				LogDebug("Failed to connect, will retry soon: %v", err)
				// When there is only one endpoint, wait a bit between attempts
				if len(backend.urls) < 2 {
					time.Sleep(backend.conn_timeout / 2)
				}
			}
		} else {
			ch, err := cnx.Channel()
			if err != nil {
				LogDebug("Failed to open AMQP channel: %v", err)
				cnx.Close()
			} else {
				backend.cnx = cnx
				backend.channel = ch
			}
		}
	}
	return nil
}

func (backend *amqpBackend) push(event []byte, routingKey string) {

	ctx, cancel := context.WithTimeout(context.Background(), backend.send_timeout)
	defer cancel()

	sent := false

loop:
	for !sent {
		// Lazy connect
		err := backend.connect()
		if err == nil {
			// Publish if possible
			msg := amqp.Publishing{
				Body: event,
			}
			err = backend.channel.PublishWithContext(
				ctx, backend.exchange, routingKey, false, false, msg)
			// Disconnect in case of error
			if err != nil {
				LogDebug("Failed to push event: %v", err)
				backend.close()
			} else {
				sent = true
			}
		}
		// If there is an error and we reached the deadline, trash the event.
		if err != nil {
			select {
			case <-ctx.Done():
				deadLetter(event, err)
				break loop
			default:
				continue
			}
		}
	}
}

func (backend *amqpBackend) close() {
	if backend.channel != nil {
		backend.channel.Close()
		backend.channel = nil
	}
	if backend.cnx != nil {
		backend.cnx.Close()
		backend.cnx = nil
	}
}

func (backend *kafkaBackend) connect() error {

	if backend.producer != nil {
		// Producer is already initialized
		return nil
	}

	LogDebug("Connecting to event broker #%s", backend.endpoint)
	producer, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers": strings.ReplaceAll(backend.endpoint, "kafka://", ""),
		"acks":              "all",
	})

	if err != nil {
		LogDebug("Failed to connect %v", err)
		return err
	}

	backend.producer = producer

	go func() {
		for e := range producer.Events() {
			switch ev := e.(type) {
			case *kafka.Message:
				if ev.TopicPartition.Error != nil {
					fmt.Printf("Failed to deliver message: %v\n", ev.TopicPartition)
				} else {
					fmt.Printf("Produced event to topic %s: key = %-10s value = %s\n",
						*ev.TopicPartition.Topic, string(ev.Key), string(ev.Value))
				}
			}
		}
	}()

	return nil
}

func (backend *kafkaBackend) push(event []byte, routingKey string) {

	err := backend.connect()

	if err == nil {

		err = backend.producer.Produce(&kafka.Message{
			TopicPartition: kafka.TopicPartition{
				Topic:     &backend.topic,
				Partition: kafka.PartitionAny,
			},
			Value: event,
		}, nil)

		if err != nil {
			LogDebug("Failed to push event: %v", err)
		}
	}
}

func (backend *kafkaBackend) close() {
	if backend.producer == nil {
		return
	}

	backend.producer.Flush(int(10 * 1000))
	backend.producer.Close()
}

func makeSingleBackend(url string, options *optionsMap) (notifierBackend, error) {
	conn_attempts := options.getInt("event_conn_attempts", eventConnAttempts)
	conn_timeout := time.Duration(
		options.getFloat("timeout_conn_event", timeoutConnEvent)) * time.Second
	send_timeout := time.Duration(
		options.getFloat("timeout_send_event", timeoutSendEvent)) * time.Second
	if endpoint, ok := hasPrefix(url, "beanstalk://"); ok {
		out := new(beanstalkdBackend)
		out.endpoint = endpoint
		out.tube = beanstalkNotifierDefaultTube
		out.conn_attempts = conn_attempts
		out.conn_timeout = conn_timeout
		return out, nil
	} else if _, ok := hasPrefix(url, "amqp://"); ok {
		out := new(amqpBackend)
		out.urls = strings.Split(url, ";")
		out.urlId = 0
		// The namespace comes from rawx configuration, but the exchange
		// comes from the namespace configuration file.
		out.exchange = oioGetConfigValue(
			options.getString("ns", "OIO"), oioConfigEventExchange)
		if out.exchange == "" {
			out.exchange = "oio"
		}
		out.conn_attempts = conn_attempts
		out.conn_timeout = conn_timeout
		out.send_timeout = send_timeout
		return out, nil
	} else if _, ok := hasPrefix(url, "kafka://"); ok {
		out := new(kafkaBackend)
		out.endpoint = url
		out.topic = oioGetConfigValue(
			options.getString("ns", "OIO"), oioConfigEventTopic)
		if out.topic == "" {
			out.topic = "oio"
		}
		return out, nil
	}
	return nil, errors.New("Unexpected notification endpoint, only `beanstalk://" +
		"`kafka://` and `amqp://` are accepted")
}

func MakeNotifier(evtUrl string, options *optionsMap, rawx *rawxService) (*notifier, error) {
	n := new(notifier)
	n.queue = make(chan routedEvent, notifierDefaultPipeSize)
	n.running = true
	n.url = rawx.url
	n.srvid = rawx.id

	workers := make([]notifierBackend, 0)
	if !strings.Contains(evtUrl, ";") || strings.HasPrefix(evtUrl, "amqp://") {
		for i := 0; i < notifierSingleMultiplier; i++ {
			backend, err := makeSingleBackend(evtUrl, options)
			if err != nil {
				return nil, err
			} else {
				workers = append(workers, backend)
			}
		}
	} else {
		for _, singleUrl := range strings.Split(evtUrl, ";") {
			for i := 0; i < notifierMultipleMultiplier; i++ {
				backend, err := makeSingleBackend(singleUrl, options)
				if err != nil {
					return nil, err
				} else {
					workers = append(workers, backend)
				}
			}
		}
	}

	n.wg.Add(len(workers))
	doWork := func(backend notifierBackend, input <-chan routedEvent) {
		defer n.wg.Done()
		for event := range input {
			if n.running {
				backend.push(event.event, event.routingKey)
			} else {
				deadLetter(event.event, errExiting)
			}
		}
		backend.close()
	}

	for _, backend := range workers {
		go doWork(backend, n.queue)
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
			case n.queue <- routedEvent{event, eventType}:
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
