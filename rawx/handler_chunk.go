// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
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
	"compress/flate"
	"compress/lzw"
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

func (rr *rawxRequest) checksumRequired() bool {
	return rr.rawx.checksumMode == checksumAlways || (rr.rawx.checksumMode == checksumSmart && !strings.HasPrefix(rr.chunk.ContentStgPol, "ec/"))
}

func (rr *rawxRequest) putData(out io.Writer) (uploadInfo, error) {
	var in io.Reader = rr.req.Body
	var h hash.Hash

	// Trigger the checksum only if configured so
	if rr.checksumRequired() {
		h = md5.New()
		in = io.TeeReader(rr.req.Body, h)
	}

	ul := uploadInfo{}
	buffer := make([]byte, rr.rawx.bufferSize, rr.rawx.bufferSize)
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

	// In specific cases where the final chunk size is known, it might be useful to prepare a space on disk.
	if rr.req.ContentLength > 0 {
		out.Extend(rr.req.ContentLength)
	}

	var ul uploadInfo

	// Maybe intercept the upload with a compression filter
	var z io.WriteCloser
	switch rr.rawx.compression {
	case compressionZlib:
		z = zlib.NewWriter(out)
	case compressionDeflate:
		z, err = flate.NewWriter(out, 1)
	case compressionLzw:
		z = lzw.NewWriter(out, lzw.MSB, 8)
	case "", compressionOff:
		z = nil
	default:
		err = errCompressionNotManaged
	}

	// Upload, and maybe manage compression
	if z != nil {
		ul, err = rr.putData(z)
		errClose := z.Close()
		if err == nil {
			err = errClose
		}
	} else if err == nil {
		ul, err = rr.putData(out)
		if err != nil {
			LogError("Chunk upload error: %s (reqid=%s)", err, rr.reqid)
		}
	}

	// If a hash has been sent, it must match the hash computed
	if err == nil {
		rr.chunk.compression = rr.rawx.compression
		if err = rr.chunk.retrieveTrailers(&rr.req.Trailer, &ul); err != nil {
			LogError("Trailer error: %s (reqid=%s)", err, rr.reqid)
		}
	}

	// If everything went well, finish with the chunks XATTR management
	if err == nil {
		if err = rr.chunk.saveAttr(out); err != nil {
			LogError("Save attr error: %s (reqid=%s)", err, rr.reqid)
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
			LogError("Save attr error: %s (reqid=%s)", err, rr.reqid)
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
	chunkIn, err := rr.rawx.repo.get(rr.chunkID)
	if err != nil {
		rr.replyError(err)
		return
	}
	defer chunkIn.Close()

	err = rr.chunk.loadAttr(chunkIn, rr.chunkID, rr.reqid)
	if err != nil {
		LogError("Failed to load xattr: %s (reqid=%s)", err, rr.reqid)
		rr.replyError(err)
		return
	}

	if GetBool(rr.req.Header.Get(HeaderNameCheckHash), false) {
		expected_hash := rr.req.Header.Get(HeaderNameChunkChecksum)
		if expected_hash == "" {
			expected_hash = rr.chunk.ChunkHash
		}
		expected_hash = strings.ToUpper(expected_hash)

		var filter io.ReadCloser
		var in *io.LimitedReader
		in, filter, err = rr.getChunkReader(chunkIn, rr.chunk.size, rangeInfo{})
		if err != nil {
			rr.replyCode(http.StatusPreconditionFailed)
			return
		}
		if filter != nil {
			defer filter.Close()
		}

		h := md5.New()
		if _, err = io.Copy(h, in); err == nil {
			actual_hash := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
			if expected_hash != actual_hash {
				rr.replyCode(http.StatusPreconditionFailed)
				return
			}
		}
		if err != nil {
			rr.replyError(err)
			return
		}
	}

	headers := rr.rep.Header()
	rr.chunk.fillHeaders(headers)
	headers.Set("Content-Length", strconv.FormatUint(uint64(rr.chunk.size), 10))
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

	if err = rr.chunk.loadAttr(inChunk, rr.chunkID, rr.reqid); err != nil {
		rr.replyError(err)
		return
	}

	var rangeInf rangeInfo
	// A potential decompression filter
	var filter io.ReadCloser
	// Actual reader that will be used
	var in *io.LimitedReader

	// Load the range, with the specific case of the compression
	rangeInf, err = rr.getRange(rr.chunk.size)
	if err != nil {
		rr.replyError(err)
		return
	}

	in, filter, err = rr.getChunkReader(inChunk, rr.chunk.size, rangeInf)
	if filter != nil {
		defer filter.Close()
	}
	if err != nil {
		rr.replyError(err)
		return
	}

	// Prepare the headers of the reply
	headers := rr.rep.Header()
	rr.chunk.fillHeaders(headers)
	if !rangeInf.isVoid() {
		headers.Set("Content-Range", fmt.Sprintf("bytes %v-%v/%v",
			rangeInf.offset, rangeInf.last, rr.chunk.size))
		headers.Set("Content-Length", strconv.FormatUint(uint64(rangeInf.size), 10))
		rr.replyCode(http.StatusPartialContent)
	} else {
		headers.Set("Content-Length", strconv.FormatUint(uint64(rr.chunk.size), 10))
		rr.replyCode(http.StatusOK)
	}

	// Now transmit the clear data to the client
	nb, err := io.Copy(rr.rep, in)
	if err == nil {
		rr.bytesOut = rr.bytesOut + uint64(nb)
	} else {
		LogError("Write() error: %s (reqid=%s)", err, rr.reqid)
	}
}

func (rr *rawxRequest) getChunkReader(inChunk fileReader, cs int64, ri rangeInfo) (in *io.LimitedReader, filter io.ReadCloser, err error) {
	// !!!(jfs): we do not manage requests on multiple ranges
	// TODO(jfs): is a multiple range is encountered, we should follow the norm
	// that allows us to answer a "200 OK" with the complete content.
	switch rr.chunk.compression {
	case compressionZlib:
		filter, err = zlib.NewReader(inChunk.File())
	case compressionLzw:
		filter = lzw.NewReader(inChunk.File(), lzw.MSB, 8)
	case compressionDeflate:
		filter = flate.NewReader(inChunk.File())
	case "", compressionOff:
		filter = nil
	default:
		err = errCompressionNotManaged
	}

	if err == nil {
		if filter != nil {
			// Skip unwanted bytes to match the range
			if !ri.isVoid() {
				_, err = io.CopyN(ioutil.Discard, filter, ri.offset)
				in = &io.LimitedReader{R: filter, N: ri.size}
			} else {
				in = &io.LimitedReader{R: filter, N: cs}
			}
		} else {
			// No compression, we can serve the raw file
			in = &io.LimitedReader{R: inChunk.File(), N: cs}
			if !ri.isVoid() {
				err = inChunk.seek(ri.offset)
				in.N = ri.size
			}
		}
	}

	return in, filter, err
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
		rr.replyError(err)
		return
	}

	err = rr.rawx.repo.del(rr.chunkID)
	if err != nil {
		if !os.IsNotExist(err) {
			LogWarning("Failed to remove chunk %s", err)
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
