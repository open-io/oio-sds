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

const bufferSize int64 = 1024 * 1024

var (
	AttrValueZLib = []byte{'z', 'l', 'i', 'b'}
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
	ErrContentLength         = errors.New("Invalid content length")
)

type uploadInfo struct {
	length int64
	hash   string
}

// Check and load a canonic form of the ID of the chunk.
func (rr *rawxRequest) retrieveChunkID() error {
	chunkID := filepath.Base(rr.req.URL.Path)
	if !isHexaString(chunkID, 64) {
		return ErrInvalidChunkID
	}
	rr.chunkID = strings.ToUpper(chunkID)
	return nil
}

func (rr *rawxRequest) putData(out io.Writer) (*uploadInfo, error) {
	contentLength := rr.req.ContentLength
	buffer := make([]byte, bufferSize)
	chunkIn := rr.req.Body
	var chunkLength int64
	chunkHash := md5.New()
	LogDebug("Uploading %v bytes", contentLength)

	for {
		max := bufferSize
		if contentLength > 0 {
			remaining := contentLength - chunkLength
			if remaining < bufferSize {
				max = remaining + 1
			}
		}
		n, err := chunkIn.Read(buffer[:max])
		LogDebug("consumed %v / %s", n, err)
		if n > 0 {
			chunkLength += int64(n)
			out.Write(buffer[:n])
			chunkHash.Write(buffer[:n])
		}
		if err != nil {
			if err == io.EOF {
				// Clean end of chunked stream
				break
			} else {
				// Any other error
				return nil, err
			}
		}
		if contentLength >= 0 && chunkLength > contentLength {
			return nil, ErrContentLength
		}
	}
	if contentLength >= 0 && chunkLength != contentLength {
		return nil, ErrContentLength
	}

	ul := new(uploadInfo)
	ul.hash = strings.ToUpper(hex.EncodeToString(chunkHash.Sum(make([]byte, 0))))
	ul.length = chunkLength
	return ul, nil
}

func (rr *rawxRequest) uploadChunk() {
	if err := rr.chunk.retrieveHeaders(&rr.req.Header, rr.chunkID); err != nil {
		LogError("Header error: %s", err)
		rr.replyError(err)
		// Discard request body
		io.Copy(ioutil.Discard, rr.req.Body)
		return
	}

	// Attempt a PUT in the repository
	out, err := rr.rawx.repo.Put(rr.chunkID)
	if err != nil {
		LogError("Chunk opening error: %s", err)
		rr.replyError(err)
		// Discard request body
		io.Copy(ioutil.Discard, rr.req.Body)
		return
	}

	// Upload, and maybe manage compression
	var ul *uploadInfo
	if rr.rawx.compress {
		z := zlib.NewWriter(out)
		ul, err = rr.putData(z)
		errClose := z.Close()
		if err == nil {
			err = errClose
		}
	} else {
		if ul, err = rr.putData(out); err != nil {
			LogError("Chunk upload error: %s", err)
		}
	}

	// If a hash has been sent, it must match the hash computed
	if err == nil {
		if err = rr.chunk.retrieveTrailers(&rr.req.Trailer, ul); err != nil {
			LogError("Trailer error: %s", err)
		}
	}

	// If everything went well, finish with the chunks XATTR management
	if err == nil {
		if err = rr.chunk.saveAttr(out); err != nil {
			LogError("Save attr error: %s", err)
		}
	}

	if err == nil {
		NotifyNew(rr.rawx.notifier, rr.reqid, &rr.chunk)
	}

	// Then reply
	if err != nil {
		rr.replyError(err)
		out.Abort()
		// Discard request body
		io.Copy(ioutil.Discard, rr.req.Body)
	} else {
		out.Commit()
		rr.rep.Header().Set("chunkhash", ul.hash)
		rr.replyCode(http.StatusCreated)
	}
}

func (rr *rawxRequest) copyChunk() {
	if err := rr.chunk.retrieveDestinationHeader(&rr.req.Header,
		rr.rawx, rr.chunkID); err != nil {
		LogError("Header error: %s", err)
		rr.replyError(err)
		return
	}
	if err := rr.chunk.retrieveContentFullpathHeader(&rr.req.Header); err != nil {
		LogError("Header error: %s", err)
		rr.replyError(err)
		return
	}

	// Attempt a LINK in the repository
	out, err := rr.rawx.repo.Link(rr.chunkID, rr.chunk.ChunkID)
	if err != nil {
		LogError("Link error: %s", err)
		rr.replyError(err)
		return
	}

	if err = rr.chunk.saveContentFullpathAttr(out); err != nil {
		LogError("Save attr error: %s", err)
	}

	// Then reply
	if err != nil {
		rr.replyError(err)
		out.Abort()
	} else {
		out.Commit()
		rr.replyCode(http.StatusCreated)
	}
}

func (rr *rawxRequest) checkChunk() {
	in, err := rr.rawx.repo.Get(rr.chunkID)
	if in != nil {
		defer in.Close()
	}
	if err != nil {
		rr.replyError(err)
		return
	}

	err = rr.chunk.loadAttr(in, rr.chunkID)
	if err != nil {
		LogError("Load attr error: %s", err)
		rr.replyError(err)
		return
	}

	headers := rr.rep.Header()
	rr.chunk.fillHeaders(&headers)
	headers.Set("Content-Length", fmt.Sprintf("%v", in.Size()))
	headers.Set("Accept-Ranges", "bytes")

	rr.replyCode(http.StatusNoContent)
}

func (rr *rawxRequest) downloadChunk() {
	inChunk, err := rr.rawx.repo.Get(rr.chunkID)
	if inChunk != nil {
		defer inChunk.Close()
	}
	if err != nil {
		LogError("File error: %s", err)
		rr.replyError(err)
		return
	}

	// Load a possible range in the request
	// !!!(jfs): we do not manage requests on multiple ranges
	// TODO(jfs): is a multiple range is encountered, we should follow the norm
	// that allows us to answer a "200 OK" with the complete content.
	length := inChunk.Size()
	headerRange := rr.req.Header.Get("Range")
	var offset, size int64
	if len(headerRange) > 0 {
		var nb int
		var last int64
		nb, err := fmt.Fscanf(strings.NewReader(headerRange), "bytes=%d-%d", &offset, &last)
		if err != nil || nb != 2 ||
			offset < 0 || last >= length || last < offset {
			rr.replyError(ErrInvalidRange)
			return
		}
		size = last - offset + 1
	}

	if err = rr.chunk.loadAttr(inChunk, rr.chunkID); err != nil {
		LogError("Load attr error: %s", err)
		rr.replyError(err)
		return
	}

	hasRange := func() bool {
		return len(headerRange) > 0
	}

	// Check if there is some compression
	var v []byte
	var in io.ReadCloser
	v, err = inChunk.GetAttr(AttrNameCompression)
	if err != nil {
		if hasRange() && offset > 0 {
			err = inChunk.Seek(offset)
		}
		in = ioutil.NopCloser(inChunk)
		err = nil
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
	if hasRange() && size > 0 {
		in = &limitedReader{sub: in, remaining: size}
	}

	headers := rr.rep.Header()
	rr.chunk.fillHeaders(&headers)

	// Prepare the headers of the reply
	if hasRange() {
		rr.rep.Header().Set("Content-Range", fmt.Sprintf("bytes %v-%v/%v", offset, offset+size-1, size))
		rr.rep.Header().Set("Content-Length", fmt.Sprintf("%v", size))
		rr.replyCode(http.StatusPartialContent)
	} else {
		rr.rep.Header().Set("Content-Length", fmt.Sprintf("%v", length))
		rr.replyCode(http.StatusOK)
	}

	// Now transmit the clear data to the client
	buffer := make([]byte, bufferSize)
	for {
		n, err := in.Read(buffer)
		if n > 0 {
			rr.bytesOut = rr.bytesOut + uint64(n)
			rr.rep.Write(buffer[:n])
		}
		if err != nil {
			if err != io.EOF {
				LogError("Write() error: %s", err)
			}
			break
		}
	}
}

func (rr *rawxRequest) removeChunk() {
	if err := rr.rawx.repo.Del(rr.chunkID); err != nil {
		rr.replyError(err)
	} else {
		rr.replyCode(http.StatusNoContent)
	}
}

func (rr *rawxRequest) serveChunk(rep http.ResponseWriter, req *http.Request) {
	err := rr.retrieveChunkID()
	if err != nil {
		rr.replyError(err)
		return
	}
	switch req.Method {
	case "PUT":
		rr.statsTime = TimePut
		rr.statsHits = HitsPut
		rr.uploadChunk()
	case "COPY":
		rr.statsTime = TimeCopy
		rr.statsHits = HitsCopy
		rr.copyChunk()
	case "HEAD":
		rr.statsTime = TimeHead
		rr.statsHits = HitsHead
		rr.checkChunk()
	case "GET":
		rr.statsTime = TimeGet
		rr.statsHits = HitsGet
		rr.downloadChunk()
	case "DELETE":
		rr.statsTime = TimeDel
		rr.statsHits = HitsDel
		rr.removeChunk()
	default:
		rr.replyCode(http.StatusMethodNotAllowed)
	}
}
