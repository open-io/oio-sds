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
	"os"
	"strconv"
	"strings"
)

const (
	// Do not attempt a Read if the available space is less than this value
	uploadBatchSize int = 8 * 1024

	// Size of the buffer allocated for the upload
	uploadBufferSize int64 = 8 * 1024 * 1024
)

var (
	attrValueZLib = []byte{'z', 'l', 'i', 'b'}
)

const (
	HeaderNameCheckHash = "X-oio-check-hash"
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

func fillBuffer(src io.Reader, buf []byte) (written int, err error) {
	for len(buf)-written >= uploadBatchSize {
		nr, er := src.Read(buf[written:])
		if nr > 0 {
			written += nr
		}
		if er != nil {
			err = er
			break
		}
	}
	return written, err
}

func dumpBuffer(dst io.Writer, buf []byte) (written int, err error) {
	for written < len(buf) {
		wr, er := dst.Write(buf[written:])
		if wr > 0 {
			written += wr
		}
		if er != nil {
			err = er
			break
		}
	}
	if err == nil && written != len(buf) {
		err = io.ErrShortWrite
	}
	return written, err
}

func copyReadWriteBuffer(dst io.Writer, src io.Reader, buf []byte) (written int64, err error) {
	for {
		// Fill the buffer
		totalr, er := fillBuffer(src, buf)

		// Dump the buffer
		if totalr > 0 {
			nw, erw := dumpBuffer(dst, buf[:totalr])
			if nw > 0 {
				written += int64(nw)
			}
			if erw != nil {
				// Only override the mais error if no strong condition occured
				if er == nil || er == io.EOF {
					err = erw
					break
				}
			}
		}

		// Manage the read error.
		// If err is already set, this is due to a strong condition when writing
		if er != nil {
			if err == nil && er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

func (rr *rawxRequest) putData(out io.Writer) (uploadInfo, error) {
	var in io.Reader
	var h hash.Hash

	// TODO(jfs): Maybe we can toggle the MD5 computation with configuration
	h = md5.New()
	in = io.TeeReader(rr.req.Body, h)

	ul := uploadInfo{}
	buffer := make([]byte, uploadBufferSize, uploadBufferSize)
	chunkLength, err := copyReadWriteBuffer(out, in, buffer)
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
		rr.replyError(err)
		// Discard request body
		io.Copy(ioutil.Discard, rr.req.Body)
		return
	}

	// Attempt a PUT in the repository
	out, err := rr.rawx.repo.put(rr.chunkID)
	if err != nil {
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
		rr.chunk.fillHeadersLight(rr.rep.Header())
		rr.replyCode(http.StatusCreated)
		NotifyNew(rr.rawx.notifier, rr.reqid, &rr.chunk)
	}
}

func (rr *rawxRequest) copyChunk() {
	if err := rr.chunk.retrieveDestinationHeader(&rr.req.Header,
		rr.rawx, rr.chunkID); err != nil {
		rr.replyError(err)
		return
	}
	if err := rr.chunk.retrieveContentFullpathHeader(&rr.req.Header); err != nil {
		rr.replyError(err)
		return
	}

	// Attempt a LINK in the repository
	op, err := rr.rawx.repo.link(rr.chunkID, rr.chunk.ChunkID)
	if err != nil {
		rr.replyError(err)
	} else {
		// Link created, try to place an xattr
		err = rr.chunk.saveContentFullpathAttr(op)
		if err != nil {
			// Xattr failed, rollback the link itself
			LogError("Save attr error: %s", err)
			rr.replyError(err)
			// If rollback fails, is lets an error
			_ = op.rollback()
		} else {
			// The link already exists and has an xattr. Commit is a matter of sync.
			_ = op.commit()
			rr.replyCode(http.StatusCreated)
		}
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
		LogError("Failed to load xattr: %s", err)
		rr.replyError(err)
		return
	}

	if GetBool(rr.req.Header.Get(HeaderNameCheckHash), false) {
		expected_hash := rr.req.Header.Get(HeaderNameChunkChecksum)
		if expected_hash == "" {
			expected_hash = rr.chunk.ChunkHash
		}
		checksum, err := in.recomputeHash()
		if err != nil {
			/* how check return code ? */
			LogError("Fail to compute md5sum: %s", err)
			rr.replyError(err)
			return
		}
		if !strings.EqualFold(checksum, expected_hash) {
			LogError("Md5sum doesn't match: computed:%s, expected:%s",
				checksum, expected_hash)
			rr.replyCode(http.StatusPreconditionFailed)
			return
		}
	}

	headers := rr.rep.Header()
	rr.chunk.fillHeaders(headers)
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
	if err != nil {
		rr.replyError(err)
		return
	}
	defer inChunk.Close()

	// Load a possible range in the request
	// !!!(jfs): we do not manage requests on multiple ranges
	// TODO(jfs): is a multiple range is encountered, we should follow the norm
	// that allows us to answer a "200 OK" with the complete content.
	chunkSize := inChunk.size()
	rangeInf, err := rr.getRange(chunkSize)
	if err != nil {
		rr.replyError(err)
		return
	}

	if err = rr.chunk.loadAttr(inChunk, rr.chunkID); err != nil {
		rr.replyError(err)
		return
	}

	// Check if there is some compression
	in := io.LimitedReader{R: inChunk.File(), N: chunkSize}

	buf := make([]byte, 32, 32)
	if sz, err := inChunk.getAttr(AttrNameCompression, buf); err != nil {
		// The range is easy to manage with non-compressed chunks
		if !rangeInf.isVoid() {
			err = inChunk.seek(rangeInf.offset)
			in.N = rangeInf.size
		}
		err = nil
	} else {
		// TODO(jfs): manage the Range offset
		if bytes.Equal(buf[:sz], attrValueZLib) {
			//in, err = zlib.NewReader(in)
			err = errCompressionNotManaged
		} else {
			err = errCompressionNotManaged
		}
	}

	headers := rr.rep.Header()
	rr.chunk.fillHeaders(headers)

	// Prepare the headers of the reply
	if !rangeInf.isVoid() {
		headers.Set("Content-Range", fmt.Sprintf("bytes %v-%v/%v",
			rangeInf.offset, rangeInf.last, chunkSize))
		headers.Set("Content-Length", strconv.FormatUint(uint64(rangeInf.size), 10))
		rr.replyCode(http.StatusPartialContent)
	} else {
		headers.Set("Content-Length", strconv.FormatUint(uint64(chunkSize), 10))
		rr.replyCode(http.StatusOK)
	}

	// Now transmit the clear data to the client
	nb, err := io.Copy(rr.rep, &in)
	if err == nil {
		rr.bytesOut = rr.bytesOut + uint64(nb)
	} else {
		LogError("Write() error: %s", err)
	}
}

func (rr *rawxRequest) removeChunk() {
	tmp := make([]byte, 2048, 2048)
	getter := func(name, key string) (string, error) {
		nb, err := rr.rawx.repo.getAttr(name, key, tmp)
		if nb <= 0 || err != nil {
			return "", err
		} else {
			return string(tmp[:nb]), err
		}
	}

	// Load only the fullpath in an attempt to spare syscalls
	err := rr.chunk.loadFullPath(getter, rr.chunkID)
	if err != nil {
		LogError("Failed to retrieve FullPath: %s", err)
		rr.replyError(err)
		return
	}

	err = rr.rawx.repo.del(rr.chunkID)
	if err != nil {
		if !os.IsNotExist(err) {
			LogError("Failed to remove chunk %s", err)
		}
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
		if err := rr.drain(); err != nil {
			rr.replyError(err)
		} else {
			rr.downloadChunk()
		}
		spent = IncrementStatReqGet(rr)
	case "PUT":
		rr.uploadChunk()
		spent = IncrementStatReqPut(rr)
	case "DELETE":
		if err := rr.drain(); err != nil {
			rr.replyError(err)
		} else {
			rr.removeChunk()
		}
		spent = IncrementStatReqDel(rr)
	case "HEAD":
		if err := rr.drain(); err != nil {
			rr.replyError(err)
		} else {
			rr.checkChunk()
		}
		spent = IncrementStatReqHead(rr)
	case "COPY":
		if err := rr.drain(); err != nil {
			rr.replyError(err)
		} else {
			rr.copyChunk()
		}
		spent = IncrementStatReqCopy(rr)
	default:
		if err := rr.drain(); err != nil {
			rr.replyError(err)
		} else {
			rr.replyCode(http.StatusMethodNotAllowed)
		}
		spent = IncrementStatReqOther(rr)
	}

	LogHttp(AccessLogEvent{
		status:    rr.status,
		timeSpent: spent,
		bytesIn:   rr.bytesIn,
		bytesOut:  rr.bytesOut,
		method:    rr.req.Method,
		local:     rr.rawx.url,
		peer:      rr.req.RemoteAddr,
		path:      rr.req.URL.Path,
		reqId:     rr.reqid,
	})
}
