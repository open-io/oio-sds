// OpenIO SDS Go rawx
// Copyright (C) 2015-2019 OpenIO SAS
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
	"compress/zlib"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)

const (
	uploadBufferSize   int64 = 64 * 1024
	downloadBufferSize int64 = 64 * 1024
)

var (
	attrValueZLib = []byte{'z', 'l', 'i', 'b'}
)

var (
	errNotImplemented        = errors.New("Not implemented")
	errChunkExists           = errors.New("Chunk already exists")
	errInvalidChunkID        = errors.New("Invalid chunk ID")
	errCompressionNotManaged = errors.New("Compression mode not managed")
	errMissingHeader         = errors.New("Missing mandatory header")
	errInvalidHeader         = errors.New("Invalid header")
	errInvalidRange          = errors.New("Invalid range")
	errRangeNotSatisfiable   = errors.New("Range not satisfiable")
	errListMarker            = errors.New("Invalid listing marker")
	errListPrefix            = errors.New("Invalid listing prefix")
	errContentLength         = errors.New("Invalid content length")
)

type uploadInfo struct {
	length int64
	hash   string
}

type rangeInfo struct {
	offset int64
	last   int64
	size   int64
}

func (ri rangeInfo) isVoid() bool { return ri.offset == 0 && ri.size == 0 }

func (rr *rawxRequest) putData(out io.Writer) (uploadInfo, error) {
	var in io.Reader
	var h hash.Hash

	// TODO(jfs): Maybe we can toggle the MD5 computation with configuration
	h = md5.New()
	in = io.TeeReader(rr.req.Body, h)

	ul := uploadInfo{}
	buffer := make([]byte, uploadBufferSize, uploadBufferSize)
	chunkLength, err := io.CopyBuffer(out, in, buffer)
	if err != nil {
		return ul, err
	}

	if h != nil {
		bin := make([]byte, 0, 32)
		ul.hash = strings.ToUpper(hex.EncodeToString(h.Sum(bin)))
	}
	ul.length = chunkLength
	rr.bytesIn = uint64(chunkLength)
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
	out, err := rr.rawx.repo.put(rr.chunkID)
	if err != nil {
		LogError("Chunk opening error: %s", err)
		rr.replyError(err)
		// Discard request body
		io.Copy(ioutil.Discard, rr.req.Body)
		return
	}

	// Upload, and maybe manage compression
	var ul uploadInfo
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
		if err = rr.chunk.retrieveTrailers(&rr.req.Trailer, &ul); err != nil {
			LogError("Trailer error: %s", err)
		}
	}

	// If everything went well, finish with the chunks XATTR management
	if err == nil {
		if err = rr.chunk.saveAttr(out); err != nil {
			LogError("Save attr error: %s", err)
		}
	}

	// Then reply
	if err != nil {
		rr.replyError(err)
		out.abort()
		// Discard request body
		io.Copy(ioutil.Discard, rr.req.Body)
	} else {
		out.commit()
		headers := rr.rep.Header()
		rr.chunk.fillHeadersLight(&headers)
		rr.replyCode(http.StatusCreated)
		NotifyNew(rr.rawx.notifier, rr.reqid, &rr.chunk)
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
	out, err := rr.rawx.repo.link(rr.chunkID, rr.chunk.ChunkID)
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
		out.abort()
	} else {
		out.commit()
		rr.replyCode(http.StatusCreated)
	}
}

func (rr *rawxRequest) checkChunk() {
	in, err := rr.rawx.repo.get(rr.chunkID)
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
	headers.Set("Content-Length", strconv.FormatUint(uint64(in.size()), 10))
	headers.Set("Accept-Ranges", "bytes")

	rr.replyCode(http.StatusOK)
}

func (rr *rawxRequest) getRange(chunkSize int64) (rangeInfo, error) {
	ri := rangeInfo{}
	headerRange := rr.req.Header.Get("Range")
	if headerRange == "" || chunkSize == 0 {
		return ri, nil
	}

	var offset int64
	var last int64
	if nb, err := fmt.Sscanf(headerRange, "bytes=%d-%d", &offset, &last); err != nil || nb != 2 {
		return ri, nil
	}
	if offset < 0 || last < 0 || offset > last {
		return ri, nil
	}
	if offset >= chunkSize {
		return ri, errInvalidRange
	}
	if last >= chunkSize {
		last = chunkSize - 1
	}
	ri.offset = offset
	ri.last = last
	ri.size = last - offset + 1
	return ri, nil
}

func (rr *rawxRequest) downloadChunk() {
	inChunk, err := rr.rawx.repo.get(rr.chunkID)
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
	chunkSize := inChunk.size()
	rangeInf, err := rr.getRange(chunkSize)
	if err != nil {
		LogError("Range error: %s", err)
		rr.replyError(err)
		return
	}

	if err = rr.chunk.loadAttr(inChunk, rr.chunkID); err != nil {
		LogError("Load attr error: %s", err)
		rr.replyError(err)
		return
	}

	// Check if there is some compression
	var v []byte
	var in io.ReadCloser
	v, err = inChunk.getAttr(AttrNameCompression)
	if err != nil {
		if !rangeInf.isVoid() {
			err = inChunk.seek(rangeInf.offset)
		}
		in = ioutil.NopCloser(inChunk)
		err = nil
	} else if bytes.Equal(v, attrValueZLib) {
		//in, err = zlib.NewReader(in)
		// TODO(jfs): manage the Range offset
		err = errCompressionNotManaged
	} else {
		err = errCompressionNotManaged
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
	if !rangeInf.isVoid() {
		in = &limitedReader{sub: in, remaining: rangeInf.size}
	}

	headers := rr.rep.Header()
	rr.chunk.fillHeaders(&headers)

	// Prepare the headers of the reply
	if !rangeInf.isVoid() {
		rr.rep.Header().Set("Content-Range", fmt.Sprintf("bytes %v-%v/%v",
			rangeInf.offset, rangeInf.last, chunkSize))
		rr.rep.Header().Set("Content-Length", strconv.FormatUint(uint64(rangeInf.size), 10))
		rr.replyCode(http.StatusPartialContent)
	} else {
		rr.rep.Header().Set("Content-Length", strconv.FormatUint(uint64(chunkSize), 10))
		rr.replyCode(http.StatusOK)
	}

	// Now transmit the clear data to the client
	buffer := make([]byte, downloadBufferSize, downloadBufferSize)
	nb, err := io.CopyBuffer(rr.rep, in, buffer)
	if err == nil {
		rr.bytesOut = rr.bytesOut + uint64(nb)
	} else {
		LogError("Write() error: %s", err)
	}
}

func (rr *rawxRequest) removeChunk() {
	in, err := rr.rawx.repo.get(rr.chunkID)
	if in != nil {
		defer in.Close()
	}
	if err != nil {
		rr.replyError(err)
		return
	}

	// Load only the fullpath
	err = rr.chunk.loadFullPath(in, rr.chunkID)
	if err != nil {
		LogError("Load attr error: %s", err)
		rr.replyError(err)
		return
	}

	err = rr.rawx.repo.del(rr.chunkID)

	if err != nil {
		rr.replyError(err)
	} else {
		rr.replyCode(http.StatusNoContent)
		NotifyDel(rr.rawx.notifier, rr.reqid, &rr.chunk)
	}
}

func (rr *rawxRequest) serveChunk() {
	if !isHexaString(rr.req.URL.Path[1:], 64) {
		rr.replyError(errInvalidChunkID)
		return
	}
	rr.chunkID = strings.ToUpper(rr.req.URL.Path[1:])

	var spent uint64
	switch rr.req.Method {
	case "GET":
		rr.downloadChunk()
		spent = IncrementStatReqGet(rr)
	case "PUT":
		rr.uploadChunk()
		spent = IncrementStatReqPut(rr)
	case "DELETE":
		rr.removeChunk()
		spent = IncrementStatReqDel(rr)
	case "HEAD":
		rr.checkChunk()
		spent = IncrementStatReqHead(rr)
	case "COPY":
		rr.copyChunk()
		spent = IncrementStatReqCopy(rr)
	default:
		rr.replyCode(http.StatusMethodNotAllowed)
		spent = IncrementStatReqOther(rr)
	}

	LogIncoming(
		rr.rawx.url, rr.req.RemoteAddr, rr.req.Method,
		rr.status, spent, rr.bytesOut,
		rr.reqid, rr.req.URL.Path)
}
