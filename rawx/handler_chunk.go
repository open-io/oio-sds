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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
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
	HeaderNameFullpath           = "X-oio-Chunk-Meta-Full-Path"
	HeaderNameContainerID        = "X-oio-Chunk-Meta-Container-Id"
	HeaderNameContentPath        = "X-oio-Chunk-Meta-Content-Path"
	HeaderNameContentVersion     = "X-oio-Chunk-Meta-Content-Version"
	HeaderNameContentID          = "X-oio-Chunk-Meta-Content-Id"
	HeaderNameContentStgPol      = "X-oio-Chunk-Meta-Content-Storage-Policy"
	HeaderNameContentChunkMethod = "X-oio-Chunk-Meta-Content-Chunk-Method"
	HeaderNameChunkPosition      = "X-oio-Chunk-Meta-Chunk-Pos"
	HeaderNameChunkSize          = "X-oio-Chunk-Meta-Chunk-Size"
	HeaderNameChunkChecksum      = "X-oio-Chunk-Meta-Chunk-Hash"
	HeaderNameMetachunkSize      = "X-oio-Chunk-Meta-Metachunk-Size"
	HeaderNameMetachunkChecksum  = "X-oio-Chunk-Meta-Metachunk-Hash"
	HeaderNameChunkID            = "X-oio-Chunk-Meta-Chunk-Id"
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
	ErrInvalidHeader         = errors.New("Invalid header")
	ErrInvalidRange          = errors.New("Invalid range")
	ErrRangeNotSatisfiable   = errors.New("Range not satisfiable")
	ErrListMarker            = errors.New("Invalid listing marker")
	ErrListPrefix            = errors.New("Invalid listing prefix")
)

type upload struct {
	in     io.Reader
	length *int64
	hash   string
}

func returnError(err error, message string) error {
	logger_error.Printf("%s: %s", err, message)
	return err
}

func cidFromName(account, container string) string {
	h := sha256.New()
	h.Write([]byte(account))
	h.Write([]byte{0})
	h.Write([]byte(container))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

// Check and load a canonic form of the ID of the chunk.
func (rr *rawxRequest) checkChunkID() error {
	chunkID := filepath.Base(rr.req.URL.Path)
	if !isHexaString(chunkID, 64) {
		return returnError(ErrInvalidChunkID, chunkID)
	}
	rr.chunk_id = strings.ToUpper(chunkID)
	return nil
}

// Check and load the content fullpath of the chunk.
func (rr *rawxRequest) checkChunkContentFullpath() error {
	headerFullpath := rr.req.Header.Get(HeaderNameFullpath)
	if headerFullpath == "" {
		return returnError(ErrMissingHeader, HeaderNameFullpath)
	}
	fullpath := strings.Split(headerFullpath, "/")
	if len(fullpath) != 5 {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}

	account, err := url.PathUnescape(fullpath[0])
	if err != nil || account == "" {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	container, err := url.PathUnescape(fullpath[1])
	if err != nil || container == "" {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	containerID := cidFromName(account, container)
	headerContainerID := rr.req.Header.Get(HeaderNameContainerID)
	if headerContainerID != "" {
		if err != nil || !strings.EqualFold(containerID, headerContainerID) {
			return returnError(ErrInvalidHeader, HeaderNameContainerID)
		}
	}

	path, err := url.PathUnescape(fullpath[2])
	if err != nil || path == "" {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	headerPath := rr.req.Header.Get(HeaderNameContentPath)
	if headerPath != "" && headerPath != path {
		return returnError(ErrInvalidHeader, HeaderNameContentPath)
	}

	version, err := url.PathUnescape(fullpath[3])
	if err != nil {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	if _, err := strconv.ParseInt(version, 10, 64); err != nil {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	headerVersion := rr.req.Header.Get(HeaderNameContentVersion)
	if headerVersion != "" && headerVersion != version {
		return returnError(ErrInvalidHeader, HeaderNameContentVersion)
	}

	contentID, err := url.PathUnescape(fullpath[4])
	if err != nil || !isHexaString(contentID, 0) {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	headerContentID := rr.req.Header.Get(HeaderNameContentID)
	if headerContentID != "" && !strings.EqualFold(headerContentID, contentID) {
		return returnError(ErrInvalidHeader, HeaderNameContentID)
	}

	beginContentID := strings.LastIndex(headerFullpath, "/") + 1
	rr.content_fullpath = headerFullpath[:beginContentID] +
		strings.ToUpper(contentID)
	return nil
}

// Check and load the info of the chunk.
func (rr *rawxRequest) checkChunkInfo() error {
	rr.content_stgpol = rr.req.Header.Get(HeaderNameContentStgPol)
	if rr.content_stgpol == "" {
		return returnError(ErrMissingHeader, HeaderNameContentStgPol)
	}
	rr.content_chunkmethod = rr.req.Header.Get(HeaderNameContentChunkMethod)
	if rr.content_chunkmethod == "" {
		return returnError(ErrMissingHeader, HeaderNameContentChunkMethod)
	}

	chunkID := rr.req.Header.Get(HeaderNameChunkID)
	if chunkID == "" && !strings.EqualFold(chunkID, rr.chunk_id) {
		return returnError(ErrInvalidHeader, HeaderNameChunkID)
	}
	rr.chunk_position = rr.req.Header.Get(HeaderNameChunkPosition)
	if rr.chunk_position == "" {
		return returnError(ErrMissingHeader, HeaderNameChunkPosition)
	}

	rr.metachunk_hash = rr.req.Header.Get(HeaderNameMetachunkChecksum)
	if rr.metachunk_hash != "" {
		if !isHexaString(rr.metachunk_hash, 0) {
			return returnError(ErrInvalidHeader, HeaderNameMetachunkChecksum)
		}
		rr.metachunk_hash = strings.ToUpper(rr.metachunk_hash)
	}
	rr.metachunk_size = rr.req.Header.Get(HeaderNameMetachunkSize)
	if rr.metachunk_size != "" {
		if _, err := strconv.ParseInt(rr.metachunk_size, 10, 64); err != nil {
			return returnError(ErrInvalidHeader, HeaderNameMetachunkSize)
		}
	}

	rr.chunk_hash = rr.req.Header.Get(HeaderNameChunkChecksum)
	if rr.chunk_hash != "" {
		if !isHexaString(rr.chunk_hash, 0) {
			return returnError(ErrInvalidHeader, HeaderNameChunkChecksum)
		}
		rr.chunk_hash = strings.ToUpper(rr.chunk_hash)
	}
	rr.chunk_size = rr.req.Header.Get(HeaderNameChunkSize)
	if rr.chunk_size != "" {
		if _, err := strconv.ParseInt(rr.chunk_size, 10, 64); err != nil {
			return returnError(ErrInvalidHeader, HeaderNameChunkSize)
		}
	}

	return rr.checkChunkContentFullpath()
}

// Check and load the checksum and the size of the chunk and the metachunk
func (rr *rawxRequest) checkChunkChecksumWithTrailers(ul *upload) error {
	trailerMetachunkHash := rr.req.Trailer.Get(HeaderNameMetachunkChecksum)
	if trailerMetachunkHash != "" {
		rr.metachunk_hash = trailerMetachunkHash
		if rr.metachunk_hash != "" {
			if !isHexaString(rr.metachunk_hash, 0) {
				return returnError(ErrInvalidHeader, HeaderNameMetachunkChecksum)
			}
			rr.metachunk_hash = strings.ToUpper(rr.metachunk_hash)
		}
	}
	trailerMetachunkSize := rr.req.Trailer.Get(HeaderNameMetachunkSize)
	if trailerMetachunkSize != "" {
		rr.metachunk_size = trailerMetachunkSize
		if rr.metachunk_size != "" {
			if _, err := strconv.ParseInt(rr.metachunk_size, 10, 64); err != nil {
				return returnError(ErrInvalidHeader, HeaderNameMetachunkSize)
			}
		}
	}
	if strings.HasPrefix(rr.content_chunkmethod, "ec/") {
		if rr.metachunk_hash == "" {
			return returnError(ErrMissingHeader, HeaderNameMetachunkChecksum)
		}
		if rr.metachunk_size == "" {
			return returnError(ErrMissingHeader, HeaderNameMetachunkSize)
		}
	}

	trailerChunkHash := rr.req.Trailer.Get(HeaderNameChunkChecksum)
	if trailerChunkHash != "" {
		rr.chunk_hash = trailerChunkHash
		rr.chunk_hash = strings.ToUpper(rr.chunk_hash)
	}
	ul.hash = strings.ToUpper(ul.hash)
	if rr.chunk_hash != "" {
		if !strings.EqualFold(rr.chunk_hash, ul.hash) {
			return returnError(ErrInvalidHeader, HeaderNameChunkChecksum)
		}
	} else {
		rr.chunk_hash = ul.hash
	}
	trailerChunkSize := rr.req.Trailer.Get(HeaderNameChunkSize)
	if trailerChunkSize != "" {
		rr.chunk_size = trailerChunkSize
	}
	if rr.chunk_size != "" {
		if _, err := strconv.ParseInt(rr.chunk_size, 10, 64); err != nil {
			return returnError(ErrInvalidHeader, HeaderNameChunkSize)
		}
	}

	return nil
}

func putData(out io.Writer, ul *upload) error {
	running := true
	remaining := *(ul.length)
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
	ul.hash = strings.ToUpper(hex.EncodeToString(sum))
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
	if err := rr.checkChunkInfo(); err != nil {
		logger_error.Print("Chunk checking error: ", err)
		rr.replyError(err)
		return
	}

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
	ul.length = &rr.req.ContentLength

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
		if err = rr.checkChunkChecksumWithTrailers(&ul); err != nil {
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
		rr.rep.Header().Set("chunkhash", ul.hash)
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
	set(HeaderNameFullpath, rr.content_fullpath)
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
