// OpenIO SDS oio-rawx-harass
// Copyright (C) 2019-2020 OpenIO SAS
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
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

const (
	stepPut    = iota
	stepGet    = iota
	stepDelete = iota
)

const (
	PFX = "X-oio-chunk-meta-"
)

var (
	rawxUrl    string = ""
	nsName     string = ""
	bufferSize uint   = 0
	buffer     []byte
	reuseCnx   = 0
)

var transport http.Transport = http.Transport{
	MaxIdleConns:       10,
	IdleConnTimeout:    30 * time.Second,
	DisableCompression: true,
}

type Scenario interface {
	SetUp(index uint)
	Step()
	TearDown()
}

type RawxClient struct {
	// Updated in refresh()
	fullPath    string
	containerId string
	contentId   string
	contentPath string
	chunkId     string
	size        uint

	// Managed by the controler
	step uint

	// Read-Only
	index uint
}

const letterBytes = "0123456789ABCDEF"
const (
	letterIdxBits = 4                    // 4 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var randMutex sync.Mutex
var randSrc = rand.NewSource(time.Now().UnixNano())

var (
	statErrorPut uint64 = 0
	statErrorGet uint64 = 0
	statErrorDel uint64 = 0
	statHitsPut  uint64 = 0
	statHitsGet  uint64 = 0
	statHitsDel  uint64 = 0
	statTimePut  uint64 = 0
	statTimeGet  uint64 = 0
	statTimeDel  uint64 = 0
	statBytesPut uint64 = 0
	statBytesGet uint64 = 0
)

// From https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go
func RandStringHexa(n int) string {
	randMutex.Lock()
	defer randMutex.Unlock()

	b := make([]byte, n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, randSrc.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSrc.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			b[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return *(*string)(unsafe.Pointer(&b))
}

func patch(req *http.Request) {
	if reuseCnx > 0 {
		req.Close = false
		req.Header.Set("Connection", "keep-alive")
	} else if reuseCnx < 0 {
		req.Close = true
		req.Header.Set("Connection", "close")
	}
}

func (rc *RawxClient) put() (int, int64) {
	url := "http://" + rawxUrl + "/" + rc.chunkId
	client := &http.Client{Transport: &transport}
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(buffer))
	patch(req)
	req.Header.Add(PFX+"full-path", rc.fullPath)
	req.Header.Add(PFX+"container-id", rc.containerId)
	req.Header.Add(PFX+"content-id", rc.contentId)
	req.Header.Add(PFX+"content-path", rc.contentPath)
	req.Header.Add(PFX+"content-storage-policy", "SINGLE")
	req.Header.Add(PFX+"content-mime-type", "octet/stream")
	req.Header.Add(PFX+"content-chunk-method", "repli/k=6,m=3")
	req.Header.Add(PFX+"chunk-pos", strconv.FormatUint(uint64(rc.index), 10))
	req.Header.Add(PFX+"oio-version", "4.2")

	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
		io.Copy(ioutil.Discard, resp.Body)
	}
	if err != nil {
		log.Println(err)
		return 0, 0
	}
	return resp.StatusCode, int64(len(buffer))
}

func (rc *RawxClient) get() (int, int64) {
	url := "http://" + rawxUrl + "/" + rc.chunkId
	client := &http.Client{Transport: &transport}
	req, _ := http.NewRequest("GET", url, nil)
	patch(req)

	var size int64
	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
		size, _ = io.Copy(ioutil.Discard, resp.Body)
	}
	if err != nil {
		log.Println(err)
		return 0, 0
	}
	return resp.StatusCode, size
}

func (rc *RawxClient) del() int {
	url := "http://" + rawxUrl + "/" + rc.chunkId
	client := &http.Client{Transport: &transport}
	req, _ := http.NewRequest("DELETE", url, nil)
	patch(req)

	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil {
		log.Println(err)
		return 0
	}
	return resp.StatusCode
}

func (rc *RawxClient) refresh() {
	//rc.size = uint(1024) + uint(rand.Intn(65536))
	rc.size = bufferSize

	account := RandStringHexa(8)
	user := RandStringHexa(8)
	version := "1"

	rc.contentPath = RandStringHexa(8)
	rc.contentId = RandStringHexa(20)
	rc.fullPath = strings.Join(
		[]string{account, user, rc.contentPath, version, rc.contentId},
		"/")
	rc.chunkId = RandStringHexa(64)

	h := sha256.New()
	h.Write([]byte(account))
	h.Write([]byte{0})
	h.Write([]byte(user))
	bin := make([]byte, 0, 32)
	rc.containerId = strings.ToUpper(hex.EncodeToString(h.Sum(bin)))
}

func (rc *RawxClient) SetUp(index uint) {
	rc.step = stepPut
	rc.index = index
}

func (rc *RawxClient) TearDown() {
	if rc.step == stepPut {
		return
	}
}

func (rc *RawxClient) Step() {
	pre := time.Now()
	switch rc.step {
	case stepPut:
		rc.refresh()
		status, size := rc.put()
		post := time.Now()
		atomic.AddUint64(&statTimePut, uint64(post.Sub(pre)))
		atomic.AddUint64(&statHitsPut, 1)
		if status/100 == 2 {
			rc.step = stepGet
			atomic.AddUint64(&statBytesPut, uint64(size))
		} else {
			atomic.AddUint64(&statErrorPut, 1)
		}
	case stepGet:
		status, size := rc.get()
		post := time.Now()
		atomic.AddUint64(&statTimeGet, uint64(post.Sub(pre)))
		atomic.AddUint64(&statHitsGet, 1)
		if status/100 == 2 {
			rc.step = stepDelete
			atomic.AddUint64(&statBytesGet, uint64(size))
		} else {
			atomic.AddUint64(&statErrorGet, 1)
		}
	case stepDelete:
		status := rc.del()
		post := time.Now()
		atomic.AddUint64(&statTimeDel, uint64(post.Sub(pre)))
		atomic.AddUint64(&statHitsDel, 1)
		if status/100 == 2 {
			rc.step = stepPut
		} else {
			atomic.AddUint64(&statErrorDel, 1)
		}
	}
}

func main() {
	var nbWorkers uint
	var nbScenarios uint
	var duration time.Duration

	flag.UintVar(&bufferSize, "size", 64, "Set the size of the buffer to be sent (kiB)")
	flag.DurationVar(&duration, "duration", 30*time.Second, "Set the duration of the whole test")
	flag.UintVar(&nbScenarios, "scenarios", 1024, "Set the number of concurrent scenarios")
	flag.UintVar(&nbWorkers, "concurrency", 16, "Set the number of concurrent coroutines")
	flag.StringVar(&nsName, "ns", "OPENIO", "Set the namespace name")
	flag.Parse()

	if flag.NArg() != 1 {
		log.Fatal("Expected unique argument: RAWX_ADDR")
	}
	if bufferSize <= 0 {
		log.Fatal("Invalid buffer size")
	}

	bufferSize = bufferSize * 1024
	buffer = make([]byte, bufferSize, bufferSize)
	rawxUrl = flag.Arg(0)
	scenarios := make([]Scenario, 0)
	pending := make(chan Scenario, 8)
	done := make(chan Scenario, 64)
	stop := make(chan os.Signal, 1)
	exited := make(chan bool)
	waiting := list.New()
	runningWorkers := 0

	// Prepare the scenarios
	for i := uint(0); i < nbScenarios; i++ {
		scenarios = append(scenarios, &RawxClient{})
	}
	for i, s := range scenarios {
		s.SetUp(uint(i))
		waiting.PushBack(s)
	}

	// Prepare the workers
	worker := func(i uint) {
		for s := range pending {
			s.Step()
			done <- s
		}
		exited <- true
	}
	for i := uint(0); i < nbWorkers; i++ {
		runningWorkers += 1
		go worker(i)
	}

	// Fire scenarios until a termination event occurs
	log.Printf("Running %d scenarios on %d workers", len(scenarios), nbWorkers)
	bell := time.After(duration)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	func() {
		// Using a function let us `return` from it much more easily than
		// breaking a `for` loop from a `select` statement
		for {
			if e := waiting.Front(); e != nil {
				select {
				case s := <-done:
					waiting.PushBack(s)
				case <-bell:
					signal.Stop(stop)
					return
				case <-stop:
					signal.Stop(stop)
					return
				case pending <- e.Value.(Scenario):
					waiting.Remove(e)
					e = nil
				}
			} else {
				// This happens when we have more workers than scenarios
				select {
				case s := <-done:
					waiting.PushBack(s)
				case <-bell:
					signal.Stop(stop)
					return
				case <-stop:
					signal.Stop(stop)
					return
				}
			}
		}
	}()

	// Termination sequence
	log.Println("Exiting the workers")
	close(pending)
	for runningWorkers > 0 {
		select {
		case <-exited:
			runningWorkers--
		case s := <-done:
			waiting.PushBack(s)
		}
	}

	waiting.Init()

	log.Println("Tearing down the scenarios")
	for _, s := range scenarios {
		s.TearDown()
	}

	s := uint64(time.Second.Nanoseconds())
	us := uint64(time.Microsecond.Nanoseconds())

	log.Println("Result:")
	if statHitsPut > 0 {
		log.Printf("put: %d hits %d err %d bytes %d us/hit %f B/s",
			statHitsPut, statErrorPut, statBytesPut,
			(statTimePut/statHitsPut)/us,
			float64(s)*(float64(statBytesPut)/float64(statTimePut)))
	} else {
		log.Println("put: none")
	}

	if statHitsGet > 0 {
		log.Printf("get: %d hits %d err %d bytes %d us/hit %f B/s",
			statHitsGet, statErrorGet, statBytesGet,
			(statTimeGet/statHitsGet)/us,
			float64(s)*(float64(statBytesGet)/float64(statTimeGet)))
	} else {
		log.Println("get: none")
	}

	if statHitsDel > 0 {
		log.Printf("del: %d hits %d err %d us/hit",
			statHitsDel, statErrorDel,
			(statTimeDel/statHitsDel)/us)
	} else {
		log.Println("del: none")
	}
}
