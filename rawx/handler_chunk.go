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
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"
)

const bufSize = 1024 * 1024

type attrMapping struct {
	attr   string
	header string
}

const (
	AttrNameMetachunkChecksum  = "user.grid.metachunk.hash"
	AttrNameMetachunkSize      = "user.grid.metachunk.size"
	AttrNameChunkChecksum      = "user.grid.chunk.hash"
	AttrNameChunkSize          = "user.grid.chunk.size"
	AttrNameChunkPosition      = "user.grid.chunk.position"
	AttrNameContentChunkMethod = "user.grid.content.chunk_method"
	AttrNameContentStgPol      = "user.grid.content.storage_policy"
	AttrNameCompression        = "user.grid.compression"
	AttrNameXattrVersion       = "user.grid.oio.version"
)

const (
	AttrNameFullPrefix = "user.grid.oio:"
)

const (
	HeaderNameContentStgPol      = "X-oio-Chunk-Meta-Content-Storage-Policy"
	HeaderNameContentChunkMethod = "X-oio-Chunk-Meta-Content-Chunk-Method"
	HeaderNameChunkPosition      = "X-oio-Chunk-Meta-Chunk-Pos"
	HeaderNameChunkSize          = "X-oio-Chunk-Meta-Chunk-Size"
	HeaderNameChunkChecksum      = "X-oio-Chunk-Meta-Chunk-Hash"
	HeaderNameMetachunkSize      = "X-oio-Chunk-Meta-Metachunk-Size"
	HeaderNameMetachunkChecksum  = "X-oio-Chunk-Meta-Metachunk-Hash"
	HeaderNameChunkID            = "X-oio-Chunk-Meta-Chunk-Id"
	HeaderNameFullPath           = "X-oio-Chunk-Meta-Full-Path"
)

var (
	AttrValueZLib []byte = []byte{'z', 'l', 'i', 'b'}
)

var (
	ErrNotImplemented        = errors.New("Not implemented")
	ErrChunkExists           = errors.New("Chunk already exists")
	ErrInvalidChunkID        = errors.New("Invalid chunk ID")
	ErrCompressionNotManaged = errors.New("Compression mode not managed")
	ErrMissingHeader         = errors.New("Missing mandatory header")
	ErrMd5Mismatch           = errors.New("MD5 sum mismatch")
	ErrInvalidRange          = errors.New("Invalid range")
	ErrRangeNotSatisfiable   = errors.New("Range not satisfiable")
	ErrListMarker            = errors.New("Invalid listing marker")
	ErrListPrefix            = errors.New("Invalid listing prefix")
)

type upload struct {
	in     io.Reader
	length int64
	h      string
}

func putData(out io.Writer, ul *upload) error {
	running := true
	remaining := ul.length
	logger_error.Printf("Uploading %v bytes", remaining)
	chunkHash := md5.New()
	buf := make([]byte, bufSize)
	for running && remaining != 0 {
		max := int64(bufSize)
		if remaining > 0 && remaining < bufSize {
			max = remaining
		}
		n, err := ul.in.Read(buf[:max])
		logger_error.Printf("consumed %v / %s", n, err)
		if n > 0 {
			if remaining > 0 {
				remaining = remaining - int64(n)
			}
			out.Write(buf[:n])
			chunkHash.Write(buf[:n])
		}
		if err != nil {
			if err == io.EOF && remaining < 0 {
				// Clean end of chunked stream
				running = false
			} else {
				// Any other error
				return err
			}
		}
	}

	sum := chunkHash.Sum(make([]byte, 0))
	ul.h = strings.ToUpper(hex.EncodeToString(sum))
	return nil
}

func putFinishChecksum(rr *rawxRequest, h string) error {

	h = strings.ToUpper(h)

	// Reload the hash from the (maybe) trailing headers
	get := func(k string) string {
		v := rr.req.Header.Get(k)
		logger_error.Printf("GetHdr %s -> %s", k, v)
		return v
	}
	rr.chunk_hash = get(HeaderNameChunkChecksum)
	rr.chunk_size = get(HeaderNameChunkSize)
	rr.metachunk_hash = get(HeaderNameMetachunkChecksum)
	rr.metachunk_size = get(HeaderNameMetachunkSize)

	if len(rr.chunk_hash) > 0 {
		if strings.ToUpper(rr.chunk_hash) != h {
			return ErrMd5Mismatch
		}
	} else {
		rr.chunk_hash = h
	}

	return nil
}

func putFinishXattr(rr *rawxRequest, out FileWriter, chunkid string) error {
	type hdrSaver struct {
		ptr *string
		key string
	}

	savers := []hdrSaver{
		{&rr.metachunk_hash, AttrNameMetachunkChecksum},
		{&rr.metachunk_size, AttrNameMetachunkSize},
		{&rr.chunk_hash, AttrNameChunkChecksum},
		{&rr.chunk_size, AttrNameChunkSize},
		{&rr.chunk_position, AttrNameChunkPosition},
		{&rr.content_chunkmethod, AttrNameContentChunkMethod},
		{&rr.content_stgpol, AttrNameContentStgPol},
	}

	set := func(k, v string) error {
		logger_error.Printf("SetAttr %v -> %v", k, v)
		if len(v) <= 0 {
			return nil
		} else {
			return out.SetAttr(k, []byte(v))
		}
	}

	for _, hs := range savers {
		if err := set(hs.key, *(hs.ptr)); err != nil {
			return err
		}
	}

	if err := set(AttrNameFullPrefix+chunkid, rr.content_fullpath); err != nil {
		return err
	}

	// TODO(jfs): svave the compression status

	return nil
}

func (rr *rawxRequest) uploadChunk() {
	// Load the HEADERS destined to be XATTR
	type hdrLoader struct {
		ptr       *string
		key       string
		mandatory bool
	}
	loaders := []hdrLoader{
		{&rr.metachunk_hash, HeaderNameMetachunkChecksum, false},
		{&rr.metachunk_size, HeaderNameMetachunkSize, false},
		{&rr.chunk_hash, HeaderNameChunkChecksum, false},
		{&rr.chunk_size, HeaderNameChunkSize, false},
		{&rr.chunk_position, HeaderNameChunkPosition, true},
		{&rr.content_chunkmethod, HeaderNameContentChunkMethod, true},
		{&rr.content_stgpol, HeaderNameContentStgPol, true},
		{&rr.content_fullpath, HeaderNameFullPath, true},
	}
	for _, hl := range loaders {
		*(hl.ptr) = rr.req.Header.Get(hl.key)
		if len(*(hl.ptr)) <= 0 && hl.mandatory {
			logger_error.Print("Missing header: ", hl.key)
			rr.replyError(ErrMissingHeader)
			return
		}
	}

	// TODO(jfs): check the format of each header

	// Attempt a PUT in the repository
	out, err := rr.rawx.repo.Put(rr.chunk_id)
	if err != nil {
		logger_error.Print("Chunk opening error: ", err)
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
		if err = putData(out, &ul); err != nil {
			logger_error.Print("Chunk upload error: ", err)
		}
	}

	// If a hash has been sent, it must match the hash computed
	if err == nil {
		if err = putFinishChecksum(rr, ul.h); err != nil {
			logger_error.Print("Chunk checksum error: ", err)
		}
	}

	// If everything went well, finish with the chunks XATTR management
	if err == nil {
		if err = putFinishXattr(rr, out, rr.chunk_id); err != nil {
			logger_error.Print("Chunk xattr error: ", err)
		}
	}

	// Then reply
	if err != nil {
		rr.replyError(err)
		out.Abort()
	} else {
		out.Commit()
		rr.rep.Header().Set("chunkhash", ul.h)
		rr.replyCode(http.StatusCreated)
	}
}

func (rr *rawxRequest) checkChunk() {
	in, err := rr.rawx.repo.Get(rr.chunk_id)
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

func (rr *rawxRequest) downloadChunk() {
	// Get a handle on the chunk then load all its XATTR
	inChunk, err := rr.rawx.repo.Get(rr.chunk_id)
	if inChunk != nil {
		defer inChunk.Close()
	}
	if err != nil {
		logger_error.Print("File error: ", err)
		rr.replyError(err)
		return
	} else {
		get := func(k string) string {
			v, _ := inChunk.GetAttr(k)
			logger_error.Printf("GetAttr %s -> %s", k, string(v))
			return string(v)
		}
		// Load all the chunks attr
		rr.chunk_size = get(AttrNameChunkSize)
		rr.chunk_hash = get(AttrNameChunkChecksum)
		rr.chunk_position = get(AttrNameChunkPosition)
		rr.content_chunkmethod = get(AttrNameContentChunkMethod)
		rr.content_stgpol = get(AttrNameContentStgPol)
		rr.metachunk_size = get(AttrNameMetachunkSize)
		rr.metachunk_hash = get(AttrNameMetachunkChecksum)
		rr.content_fullpath = get(AttrNameFullPrefix + rr.chunk_id)
	}

	// Load a possible range in the request
	// !!!(jfs): we do not manage requests on multiple ranges
	// TODO(jfs): is a multiple range is encountered, we should follow the norm
	// that allows us to answer a "200 OK" with the complete content.
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
	v, err = inChunk.GetAttr(AttrNameCompression)
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

	// Fill the headers of the reply with the attributes of the chunk
	set := func(k, v string) {
		logger_error.Printf("SetHdr %v -> %v", k, v)
		if len(v) > 0 {
			rr.rep.Header().Set(k, v)
		}
	}
	set(HeaderNameChunkChecksum, rr.chunk_hash)
	set(HeaderNameChunkSize, rr.chunk_size)
	set(HeaderNameMetachunkChecksum, rr.metachunk_hash)
	set(HeaderNameMetachunkSize, rr.metachunk_size)
	set(HeaderNameContentStgPol, rr.content_stgpol)
	set(HeaderNameContentChunkMethod, rr.content_chunkmethod)
	set(HeaderNameFullPath, rr.content_fullpath)
	set(HeaderNameChunkID, rr.chunk_id)

	// Prepare the headers of the reply
	if has_range() {
		rr.rep.Header().Set("Content-Range", fmt.Sprintf("bytes %v-%v/%v", offset, offset+size, size))
		rr.rep.Header().Set("Content-Length", fmt.Sprintf("%v", size))
		if size <= 0 {
			rr.replyCode(http.StatusNoContent)
		} else {
			rr.replyCode(http.StatusPartialContent)
		}
	} else {
		length := inChunk.Size()
		rr.rep.Header().Set("Content-Length", fmt.Sprintf("%v", length))
		if length <= 0 {
			rr.replyCode(http.StatusNoContent)
		} else {
			rr.replyCode(http.StatusOK)
		}
	}

	// Now transmit the clear data to the client
	buf := make([]byte, bufSize)
	for {
		n, err := in.Read(buf)
		if n > 0 {
			rr.bytes_out = rr.bytes_out + uint64(n)
			rr.rep.Write(buf[:n])
		}
		if err != nil {
			if err != io.EOF {
				logger_error.Print("Write() error: ", err)
			}
			break
		}
	}
}

func (rr *rawxRequest) removeChunk() {
	if err := rr.rawx.repo.Del(rr.chunk_id); err != nil {
		rr.replyError(err)
	} else {
		rr.replyCode(http.StatusNoContent)
	}
}

// Check and load a canonic form of the ID of the chunk.
func (rr *rawxRequest) checkChunkID() error {
	chunkID := filepath.Base(rr.req.URL.Path)
	if !isHexaString(chunkID, 64) {
		return ErrInvalidChunkID
	}
	rr.chunk_id = strings.ToUpper(chunkID)
	return nil
}

func (rr *rawxRequest) serveChunk(rep http.ResponseWriter, req *http.Request) {
	err := rr.checkChunkID()
	if err != nil {
		rr.replyError(err)
		return
	}
	switch req.Method {
	case "PUT":
		rr.stats_time = TimePut
		rr.stats_hits = HitsPut
		rr.uploadChunk()
	case "HEAD":
		rr.stats_time = TimeHead
		rr.stats_hits = HitsHead
		rr.checkChunk()
	case "GET":
		rr.stats_time = TimeGet
		rr.stats_hits = HitsGet
		rr.downloadChunk()
	case "DELETE":
		rr.stats_time = TimeDel
		rr.stats_hits = HitsDel
		rr.removeChunk()
	default:
		rr.replyCode(http.StatusMethodNotAllowed)
	}
}
