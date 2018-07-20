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
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
	"strings"
)

type chunkHandler struct {
	rawx *rawxService
}

type attrMapping struct {
	attr   string
	header string
}

const bufSize = 16384

var AttrMap []attrMapping = []attrMapping{
	{AttrNameAlias, "Alias"},
	{AttrNameStgPol, "Chunk-Meta-Content-Storage-Policy"},
	{AttrNameMimeType, "Chunk-Meta-Content-Mime-Type"},
	{AttrNameChunkMethod, "Chunk-Meta-Content-Chunk-Method"},
	{AttrNameChunkId, "Chunk-Meta-Chunk-Id"},
	{AttrNameSize, "Chunk-Meta-Chunk-Size"},
	{AttrNamePosition, "Chunk-Meta-Chunk-Pos"},
	{AttrNameChecksum, "Chunk-Meta-Chunk-Hash"},
}

var mandatoryHeaders = []string{
	AttrNameStgPol,
	AttrNameMimeType,
	AttrNameChunkMethod,
	AttrNameChunkId,
	AttrNameSize,
	AttrNamePosition,
}

type upload struct {
	in     io.Reader
	length int64
	h      string
}

func putData(out io.Writer, ul *upload) error {
	remaining := ul.length
	chunkHash := md5.New()
	buf := make([]byte, bufSize)
	for remaining > 0 {
		max := remaining
		if max > bufSize {
			max = bufSize
		}
		n, err := ul.in.Read(buf[:max])
		if n > 0 {
			out.Write(buf[:n])
			chunkHash.Write(buf[:n])
			remaining = remaining - int64(n)
		}
		if err != nil {
			return err
		}
	}

	sum := chunkHash.Sum(make([]byte, 0))
	ul.h = strings.ToUpper(hex.EncodeToString(sum))
	return nil
}

func putFinish(rr *rawxRequest, out FileWriter, h string) error {

	// If a hash has been sent, it must match the hash computed
	h = strings.ToUpper(h)
	if h0, ok := rr.xattr[AttrNameChecksum]; ok && len(h0) > 0 {
		if strings.ToUpper(h0) != h {
			return ErrMd5Mismatch
		}
	} else {
		rr.xattr[AttrNameChecksum] = h
	}

	for k, v := range rr.xattr {
		if err := out.SetAttr(AttrPrefix+k, []byte(v)); err != nil {
			return err
		}
	}

	return nil
}

func uploadChunk(rr *rawxRequest, chunkid string) {

	// Check all the mandatory headers are present
	for _, pair := range AttrMap {
		if v := rr.req.Header.Get(HeaderPrefix + pair.header); v != "" {
			rr.xattr[pair.attr] = v
		}
	}

	// Check all the mandatory headers are present
	for _, k := range mandatoryHeaders {
		if _, ok := rr.xattr[k]; !ok {
			rr.rawx.logger_error.Print("Missing header %s", k)
			rr.replyError(ErrMissingHeader)
			return
		}
	}

	// Attempt a PUT in the repository
	out, err := rr.rawx.repo.Put(chunkid)
	if err != nil {
		rr.replyError(err)
		return
	}

	// Upload, and maybe manage compression
	var ul upload
	ul.in = rr.req.Body
	ul.length = rr.req.ContentLength

	if rr.rawx.compress {
		z := zlib.NewWriter(out)
		err = putData(z, &ul)
		errClose := z.Close()
		if err == nil {
			err = errClose
		}
	} else {
		err = putData(out, &ul)
	}

	// Finish with the XATTR management
	if err != nil {
		err = putFinish(rr, out, ul.h)
	}

	// Then reply
	if err != nil {
		rr.replyError(err)
		out.Abort()
	} else {
		out.Commit()
		rr.rep.Header().Set("chunkhash", ul.h)
		rr.replyCode(http.StatusOK)
	}
}

func checkChunk(rr *rawxRequest, chunkid string) {
	in, err := rr.rawx.repo.Get(chunkid)
	if in != nil {
		defer in.Close()
	}

	length := in.Size()
	rr.rep.Header().Set("Content-Length", fmt.Sprintf("%v", length))
	rr.rep.Header().Set("Accept-Ranges", "bytes")

	if err != nil {
		rr.replyError(err)
	} else {
		rr.replyCode(http.StatusNoContent)
	}
}

func downloadChunk(rr *rawxRequest, chunkid string) {
	inChunk, err := rr.rawx.repo.Get(chunkid)
	if inChunk != nil {
		defer inChunk.Close()
	}
	if err != nil {
		rr.replyError(err)
		return
	}

	hdr_range := rr.req.Header.Get("Range")
	var offset, size int64
	if len(hdr_range) > 0 {
		var nb int
		var last int64
		nb, err := fmt.Fscanf(strings.NewReader(hdr_range), "bytes=%d-%d", &offset, &last)
		if err != nil || nb != 2 || last <= offset {
			rr.replyError(ErrInvalidRange)
			return
		}
		size = last - offset + 1
	}

	has_range := func() bool {
		return len(hdr_range) > 0
	}

	// Check if there is some compression
	var v []byte
	var in io.ReadCloser
	v, err = inChunk.GetAttr(AttrPrefix + AttrNameCompression)
	if err != nil {
		if has_range() && offset > 0 {
			err = inChunk.Seek(offset)
		} else {
			in = ioutil.NopCloser(inChunk)
			err = nil
		}
	} else if bytes.Equal(v, AttrValueZLib) {
		//in, err = zlib.NewReader(in)
		// TODO(jfs): manage the Range offset
		err = ErrCompressionNotManaged
	} else {
		err = ErrCompressionNotManaged
	}

	if in != nil {
		defer in.Close()
	}
	if err != nil {
		setError(rr.rep, err)
		rr.replyCode(http.StatusInternalServerError)
		return
	}

	// If the range specified a size, let's wrap (again) the input
	if has_range() && size > 0 {
		in = &limitedReader{sub: in, remaining: size}
	}

	for _, pair := range AttrMap {
		v, err := inChunk.GetAttr(AttrPrefix + pair.attr)
		if err != nil {
			rr.rep.Header().Set(pair.header, string(v))
		}
	}

	if has_range() {
		rr.rep.Header().Set("Content-Length", fmt.Sprintf("%v", size))
	} else {
		length := inChunk.Size()
		rr.rep.Header().Set("Content-Length", fmt.Sprintf("%v", length))
	}

	// Now transmit the clear data to the client
	rr.replyCode(http.StatusOK)
	buf := make([]byte, bufSize)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			rr.bytes_out = rr.bytes_out + uint64(n)
			rr.rep.Write(buf[:n])
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("Write() error : %v", err)
			}
			break
		}
	}
}

func removeChunk(rr *rawxRequest, chunkid string) {
	if err := rr.rawx.repo.Del(chunkid); err != nil {
		rr.replyError(err)
	} else {
		rr.replyCode(http.StatusNoContent)
	}
}

func (self *chunkHandler) ServeHTTP(rep http.ResponseWriter, req *http.Request) {
	self.rawx.serveHTTP(rep, req, func(rr *rawxRequest) {
		chunkid := filepath.Base(req.URL.Path)
		switch req.Method {
		case "PUT":
			rr.stats_time = TimePut
			rr.stats_hits = HitsPut
			uploadChunk(rr, chunkid)
		case "HEAD":
			rr.stats_time = TimeHead
			rr.stats_hits = HitsHead
			checkChunk(rr, chunkid)
		case "GET":
			rr.stats_time = TimeGet
			rr.stats_hits = HitsGet
			downloadChunk(rr, chunkid)
		case "DELETE":
			rr.stats_time = TimeDel
			rr.stats_hits = HitsDel
			removeChunk(rr, chunkid)
		default:
			rr.replyCode(http.StatusMethodNotAllowed)
		}
	})
}
