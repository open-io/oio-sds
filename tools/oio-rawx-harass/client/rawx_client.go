// OpenIO SDS oio-rawx-harass
// Copyright (C) 2019-2020 OpenIO SAS
// Copyright (C) 2021-2024 OVH SAS
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

package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"openio-sds/tools/oio-rawx-harass/utils"
)

const (
	PFX = "X-oio-chunk-meta-"
)

var (
	NsName     string = "OPENIO"
	BufferSize uint   = 1024
	buffer     []byte
	ReuseCnx   = 0
)

var transport http.Transport = http.Transport{
	MaxIdleConns:       10,
	IdleConnTimeout:    30 * time.Second,
	DisableCompression: true,
}

type RawxTarget struct {
	RawxUrl []string
}

type RawxClient struct {
	// Updated in refresh()
	fullPath    string
	containerId string
	contentId   string
	contentPath string
	chunkId     string
	size        uint

	// Read-Only
	index       uint
	targetIndex int
}

func Prepare() {
	if BufferSize <= 0 {
		log.Fatal("Invalid buffer size")
	}
	BufferSize = BufferSize * 1024
	buffer = make([]byte, BufferSize, BufferSize)
}

func patchRawxRequest(req *http.Request) {
	if ReuseCnx > 0 {
		req.Close = false
		req.Header.Set("Connection", "keep-alive")
	} else if ReuseCnx < 0 {
		req.Close = true
		req.Header.Set("Connection", "close")
	}
}

func (rc *RawxClient) GetIndex() uint {
	return rc.index
}

func (rc *RawxClient) Put(tgt *RawxTarget, st *Stats) (int, int64) {
	pre := time.Now()

	url := "http://" + tgt.RawxUrl[rc.targetIndex] + "/" + rc.chunkId
	client := &http.Client{Transport: &transport}
	req, _ := http.NewRequest("PUT", url, bytes.NewReader(buffer))
	patchRawxRequest(req)
	req.Header.Add(PFX+"full-path", rc.fullPath)
	req.Header.Add(PFX+"container-id", rc.containerId)
	req.Header.Add(PFX+"content-id", rc.contentId)
	req.Header.Add(PFX+"content-path", rc.contentPath)
	req.Header.Add(PFX+"content-storage-policy", "SINGLE")
	req.Header.Add(PFX+"content-mime-type", "octet/stream")
	req.Header.Add(PFX+"content-chunk-method", "repli/k=6,m=3")
	req.Header.Add(PFX+"chunk-pos", strconv.FormatUint(uint64(rc.index), 10))

	code := 0
	resp, err := client.Do(req)
	var size int64
	if resp != nil {
		code = resp.StatusCode
		defer resp.Body.Close()
		size, _ = io.Copy(ioutil.Discard, resp.Body)
	}
	post := time.Now()
	atomic.AddUint64(&st.TimePut, uint64(post.Sub(pre)))
	atomic.AddUint64(&st.HitsPut, 1)

	if err != nil {
		log.WithField("_id", rc.index).WithError(err).Info("PUT failed")
		atomic.AddUint64(&st.ErrorPut, 1)
		return 0, 0
	} else {
		atomic.AddUint64(&st.BytesPut, uint64(size))
		return code, size
	}
}

func (rc *RawxClient) Get(tgt *RawxTarget, st *Stats) (int, int64) {
	pre := time.Now()

	url := "http://" + tgt.RawxUrl[rc.targetIndex] + "/" + rc.chunkId
	client := &http.Client{Transport: &transport}
	req, _ := http.NewRequest("GET", url, nil)
	patchRawxRequest(req)

	code := 0
	var size int64
	resp, err := client.Do(req)
	if resp != nil {
		code = resp.StatusCode
		defer resp.Body.Close()
		size, _ = io.Copy(ioutil.Discard, resp.Body)
	}

	post := time.Now()
	atomic.AddUint64(&st.TimeGet, uint64(post.Sub(pre)))
	atomic.AddUint64(&st.HitsGet, 1)

	if err != nil {
		log.WithField("_id", rc.index).WithError(err).Info("GET failed")
		atomic.AddUint64(&st.ErrorGet, 1)
		return 0, 0
	} else {
		// log.WithField("_id", rc.index).Debug("GET succeeded")
		atomic.AddUint64(&st.BytesGet, uint64(size))
		return code, size
	}
}

func (rc *RawxClient) Del(tgt *RawxTarget, st *Stats) int {
	pre := time.Now()

	url := "http://" + tgt.RawxUrl[rc.targetIndex] + "/" + rc.chunkId
	client := &http.Client{Transport: &transport}
	req, _ := http.NewRequest("DELETE", url, nil)
	patchRawxRequest(req)

	code := 0
	resp, err := client.Do(req)
	if resp != nil {
		code = resp.StatusCode
		defer resp.Body.Close()
	}

	post := time.Now()
	atomic.AddUint64(&st.TimeDel, uint64(post.Sub(pre)))
	atomic.AddUint64(&st.HitsDel, 1)

	if err != nil {
		log.WithField("_id", rc.index).WithError(err).Info("DEL failed")
		atomic.AddUint64(&st.ErrorDel, 1)
		return 0
	} else {
		// log.WithField("_id", rc.index).Debug("DEL succeeded")
		return code
	}
}

func (rc *RawxClient) Refresh(tgt *RawxTarget, index uint) {
	rc.index = index
	rc.targetIndex = utils.RandIntRange(0, len(tgt.RawxUrl)-1)

	//rc.size = uint(1024) + uint(rand.Intn(65536))
	rc.size = BufferSize

	account := utils.RandStringHexa(8)
	user := utils.RandStringHexa(8)
	version := "1"

	rc.contentPath = utils.RandStringHexa(8)
	rc.contentId = utils.RandStringHexa(20)
	rc.fullPath = strings.Join(
		[]string{account, user, rc.contentPath, version, rc.contentId},
		"/")
	rc.chunkId = utils.RandStringHexa(64)

	h := sha256.New()
	h.Write([]byte(account))
	h.Write([]byte{0})
	h.Write([]byte(user))
	bin := make([]byte, 0, 32)
	rc.containerId = strings.ToUpper(hex.EncodeToString(h.Sum(bin)))
}
