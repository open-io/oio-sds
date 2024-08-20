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
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"openio-sds/tools/oio-rawx-harass/config"
	"openio-sds/tools/oio-rawx-harass/utils"
)

const (
	PFX = "X-oio-chunk-meta-"
)

var DisablePersist bool = false

var Config = RawxClientConfig{
	Namespace: "OPENIO",
	ReuseCnx:  1,
	Prefix:    "",
}

var transport http.Transport = http.Transport{
	MaxIdleConns:       10,
	IdleConnTimeout:    30 * time.Second,
	DisableCompression: true,
}

type RawxClient struct {
	rx      uint32
	chunkId string
}

func patchRawxRequest(req *http.Request) {
	if Config.ReuseCnx > 0 {
		req.Close = false
		req.Header.Set("Connection", "keep-alive")
	} else if Config.ReuseCnx < 0 {
		req.Close = true
		req.Header.Set("Connection", "close")
	}
}

func (rc *RawxClient) Persist(tgt *config.RawxTargets) error {
	if DisablePersist {
		return nil
	}
	return tgt.Get(rc.rx).Save(rc.chunkId)
}

func (rc *RawxClient) Forget(tgt *config.RawxTargets) error { return tgt.Get(rc.rx).Delete(rc.chunkId) }

func (rc *RawxClient) ChunkId() string { return rc.chunkId }

func (rc *RawxClient) Rawx(tgt *config.RawxTargets) string { return tgt.Get(rc.rx).URL() }

func (rc *RawxClient) LogFields(tgt *config.RawxTargets) log.Fields {
	return log.Fields{"chunk": rc.ChunkId(), "rawx": rc.Rawx(tgt)}
}

func (rc *RawxClient) Put(st *Stats, tgt *config.RawxTargets, size int64) (error, int, int64) {
	pre := time.Now()

	account := utils.RandStringHexa(8)
	user := utils.RandStringHexa(8)
	version := "1"
	contentPath := utils.RandStringHexa(8)
	contentId := utils.RandStringHexa(20)
	fullPath := strings.Join([]string{account, user, contentPath, version, contentId}, "/")
	h := sha256.New()
	h.Write([]byte(account))
	h.Write([]byte{0})
	h.Write([]byte(user))
	bin := make([]byte, 0, 32)
	containerId := strings.ToUpper(hex.EncodeToString(h.Sum(bin)))

	url := "http://" + tgt.Get(rc.rx).URL() + "/" + rc.ChunkId()

	client := &http.Client{Transport: &transport}
	req, _ := http.NewRequest("PUT", url, utils.NewRepeater(size))
	patchRawxRequest(req)
	req.Header.Add(PFX+"full-path", fullPath)
	req.Header.Add(PFX+"container-id", containerId)
	req.Header.Add(PFX+"content-id", contentId)
	req.Header.Add(PFX+"content-path", contentPath)
	req.Header.Add(PFX+"content-storage-policy", "SINGLE")
	req.Header.Add(PFX+"content-mime-type", "octet/stream")
	req.Header.Add(PFX+"content-chunk-method", "repli/k=6,m=3")
	req.Header.Add(PFX+"chunk-pos", "17")

	code := 0
	resp, err := client.Do(req)
	if err == nil {
		code = resp.StatusCode
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}

	post := time.Now()
	atomic.AddUint64(&st.TimePut, uint64(post.Sub(pre).Nanoseconds()))
	atomic.AddUint64(&st.HitsPut, 1)

	if err != nil {
		atomic.AddUint64(&st.ErrorPut, 1)
		return err, code, 0
	} else {
		atomic.AddUint64(&st.BytesPut, uint64(size))
		return nil, code, size
	}
}

func (rc *RawxClient) Get(st *Stats, tgt *config.RawxTargets) (error, int, int64) {
	url := "http://" + tgt.Get(rc.rx).URL() + "/" + rc.ChunkId()

	client := &http.Client{Transport: &transport}
	req, _ := http.NewRequest("GET", url, nil)
	patchRawxRequest(req)

	code := 0
	size := int64(0)

	pre := time.Now()
	resp, err := client.Do(req)
	if resp != nil {
		code = resp.StatusCode
		defer resp.Body.Close()
		sz, ttfb := discard(resp.Body, pre)
		atomic.AddUint64(&st.TTFB, uint64(ttfb.Nanoseconds()))
		size = sz
	}

	post := time.Now()
	atomic.AddUint64(&st.TimeGet, uint64(post.Sub(pre).Nanoseconds()))
	atomic.AddUint64(&st.HitsGet, 1)

	if err != nil {
		atomic.AddUint64(&st.ErrorGet, 1)
		return err, 0, 0
	} else {
		atomic.AddUint64(&st.BytesGet, uint64(size))
		return nil, code, size
	}
}

func (rc *RawxClient) Del(st *Stats, tgt *config.RawxTargets) (error, int) {
	pre := time.Now()

	url := "http://" + tgt.Get(rc.rx).URL() + "/" + rc.ChunkId()

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
	atomic.AddUint64(&st.TimeDel, uint64(post.Sub(pre).Nanoseconds()))
	atomic.AddUint64(&st.HitsDel, 1)

	if err != nil {
		atomic.AddUint64(&st.ErrorDel, 1)
		return err, 0
	} else {
		return nil, code
	}
}

// Refresh the random fields, thus targeting a new chunk.
// It's up to the implementation to call this when meaningful, since it will drop the existing state
func (rc *RawxClient) Refresh(tgt *config.RawxTargets) {
	rc.rx = tgt.Poll()
	prefixLength := len(Config.Prefix)
	rc.chunkId = Config.Prefix
	rc.chunkId += utils.RandStringHexa(64 - prefixLength)
}

func (rc *RawxClient) Craft(tgt *config.RawxTargets, rx uint32, chunkId string) {
	rc.rx = rx
	rc.chunkId = chunkId
}

func discard(in io.Reader, pre time.Time) (int64, time.Duration) {
	var ttfb time.Duration
	var totalSize int64
	first := true
	buf := make([]byte, 8*1024)
	for {
		sz, err := in.Read(buf)
		if sz > 0 {
			totalSize += int64(sz)
		}
		if first {
			ttfb = time.Now().Sub(pre)
			first = false
		}
		if err != nil {
			return totalSize, ttfb
		}
	}
}
