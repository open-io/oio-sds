// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2021-2025 OVH SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Affero General Public License for more details.
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
	"openio-sds/rawx/concurrency"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"openio-sds/rawx/defs"
	"openio-sds/rawx/logger"
	"openio-sds/rawx/utils"

	"lukechampine.com/blake3"
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

var RangeRegex = regexp.MustCompile(`^bytes=(\d*)-(\d*)$`)

func (ri rangeInfo) isVoid() bool { return ri.offset == 0 && ri.size == 0 }

func fillBuffer(src io.Reader, buf []byte) (written int, err error) {
	for len(buf)-written >= defs.UploadBatchSize {
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

type UploadFinal func(int64, error) error

func copyReadWriteBuffer(dst io.Writer, src io.Reader, h hash.Hash, pool utils.BufferPool, cb UploadFinal) error {
	var written int64
	var err error

	buf := pool.Acquire()
	defer pool.Release(buf)

	for {
		// Fill the buffer
		totalr, er := fillBuffer(src, buf)

		if totalr > 0 {
			h.Write(buf[:totalr])
		}

		// We need to interleave the final operation before the last block,
		// It will save expensive head movements on HDD if xattr are before
		// the data when we GET
		if er == io.EOF {
			err = cb(written+int64(totalr), nil)
			if err != nil {
				logger.LogWarning("Upload Final Hook: %v", err)
				return err
			}
		}

		// Dump the buffer
		if totalr > 0 {
			nw, erw := dumpBuffer(dst, buf[:totalr])
			if nw > 0 {
				written += int64(nw)
			}
			if erw != nil {
				// Only override the main error if no strong condition occurred
				if er == nil {
					return cb(written, erw)
				}
				if er == io.EOF {
					return erw // Callback already called
				}
			}
		}

		// Manage the read error.
		// If err is already set, this is due to a strong condition when writing
		if er != nil {
			if er != io.EOF {
				return cb(written, er)
			} else {
				return nil // Callback already called
			}
		}
	}
}

func (rr *rawxRequest) checksumRequired() bool {
	return rr.rawx.checksumMode == defs.ChecksumAlways || (rr.rawx.checksumMode == defs.ChecksumSmart && !strings.HasPrefix(rr.chunk.ContentStgPol, "ec/"))
}

func (rr *rawxRequest) uploadChunk() {
	var err error
	var out fileWriter
	var h hash.Hash

	if rr.chunk, err = retrieveHeaders(&rr.req.Header, rr.chunkID); err != nil {
		rr.replyError("uploadChunk()", err)
		// Discard request body
		io.Copy(ioutil.Discard, rr.req.Body)
		return
	}

	// Attempt a PUT in the repository
	out, err = rr.rawx.repo.put(rr.chunkID)
	if err != nil {
		rr.replyError("uploadChunk()", err)
		// Discard request body
		io.Copy(ioutil.Discard, rr.req.Body)
		return
	}

	// In specific cases where the final chunk size is known, it might be useful to prepare a space on disk.
	if rr.req.ContentLength > 0 {
		out.Extend(rr.req.ContentLength)
	}

	// Trigger the checksum only if configured so
	if rr.checksumRequired() {
		switch rr.chunk.ChunkHashAlgo {
		case "blake3":
			h = blake3.New(32, nil)
		case "md5":
			h = md5.New()
		default:
			h = blake3.New(32, nil)
			rr.chunk.ChunkHashAlgo = "blake3"
		}
	}

	var ul uploadInfo

	// Maybe intercept the upload with a compression filter
	var z io.WriteCloser
	switch rr.rawx.compression {
	case defs.CompressionZlib:
		z = zlib.NewWriter(out)
	case defs.CompressionDeflate:
		z, err = flate.NewWriter(out, 1)
	case defs.CompressionLzw:
		z = lzw.NewWriter(out, lzw.MSB, 8)
	case "", defs.CompressionOff:
		z = nil
	default:
		err = errCompressionNotManaged
	}
	switch rr.rawx.compression {
	case "", defs.CompressionOff:
		rr.chunk.compression = ""
	default:
		rr.chunk.compression = rr.rawx.compression
	}

	// Destined to be called before the last chunk is written;
	final := func(written int64, err error) error {
		ul.length = written
		if err != nil {
			return err
		}
		if h != nil {
			ul.hash = strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
		}
		// If a hash has been sent, it must match the hash computed
		e := rr.chunk.patchWithTrailers(&rr.req.Trailer, ul)
		// If everything went well, finish with the chunks XATTR management
		if e != nil {
			return e
		} else {
			return rr.chunk.saveAttr(out)
		}
	}

	// Upload, and maybe manage compression
	if z != nil {
		err = copyReadWriteBuffer(z, rr.req.Body, h, rr.rawx.uploadBufferPool, final)
		errClose := z.Close()
		if err == nil {
			err = errClose
		}
	} else if err == nil {
		err = copyReadWriteBuffer(out, rr.req.Body, h, rr.rawx.uploadBufferPool, final)
	}
	rr.bytesIn = uint64(ul.length)

	// Then reply
	if err != nil {
		// Discard request body
		io.Copy(ioutil.Discard, rr.req.Body)
		rr.replyError("uploadChunk()", err)
		out.abort()
		return
	}

	out.commit()
	// If chunk placement is not optimal
	if rr.chunk.nonOptimalPlacement {
		// Ignore if link creation failed. This link creation should not be blocking as
		// a crawler would detect the non optimal placement in a near future.
		rr.rawx.repo.symlinkNonOptimal(rr.chunkID)
	}
	rr.rep.Header().Set("Connection", "keep-alive")
	rr.req.Close = false
	rr.chunk.fillHeadersLight(rr.rep.Header())
	rr.replyCode(http.StatusCreated)
	rr.rawx.notifier.NotifyNew(rr.reqid, rr.chunk)
}

func (rr *rawxRequest) updateChunk() {
	var err error
	var out fileUpdater

	// Check if chunk exists before continuing
	if !rr.rawx.repo.check(rr.chunkID) {
		rr.replyCode(http.StatusNotFound)
		return
	}

	// Retrieve all headers needed for POST operation
	if rr.chunk, err = retrievePostHeaders(&rr.req.Header, rr.chunkID); err != nil {
		rr.replyError("updateChunk() headers", err)
		return
	}

	if rr.chunk.nonOptimalPlacement {
		if err = rr.rawx.repo.symlinkNonOptimal(rr.chunkID); err != nil {
			// If the link already exists, a <ErrExist> error will be thrown,
			// leading to a <409 Conflict> to the client.
			rr.replyError("updateChunk() link", err)
			return
		}
	}

	out = rr.rawx.repo.post(rr.chunkID)
	if err = rr.chunk.saveExtMetaAttr(out); err != nil {
		rr.replyError("updateChunk()", err)
	}

	// Everything is OK, return success
	rr.replyCode(http.StatusOK)
}

func (rr *rawxRequest) copyChunk() {
	var err error
	if rr.chunk, err = retrieveDestinationHeader(&rr.req.Header, rr.rawx, rr.chunkID); err != nil {
		rr.replyError("copyChunk() dest", err)
		return
	}
	if err := rr.chunk.retrieveContentFullpathHeader(&rr.req.Header); err != nil {
		rr.replyError("copyChunk() fullpath", err)
		return
	}

	// Attempt a LINK in the repository
	op, err := rr.rawx.repo.link(rr.chunkID, rr.chunk.ChunkID)
	if err != nil {
		// TODO(FVE): if shallow copy is disabled, do a regular copy
		if err == errNotImplemented {
			rr.replyCode(http.StatusMethodNotAllowed)
		} else {
			rr.replyError("copyChunk()", err)
		}
		return
	} else {
		// Link created, try to place an xattr
		err = rr.chunk.saveContentFullpathAttr(op)
		if err != nil {
			// Xattr failed, rollback the link itself
			rr.replyError("Setxattr()", err)
			// If rollback fails, is lets an error
			_ = op.rollback()
		} else {
			// The link already exists and has an xattr. Commit is a matter of sync.
			_ = op.commit()
			rr.replyCode(http.StatusCreated)
			rr.rawx.notifier.NotifyNew(rr.reqid, rr.chunk)
		}
	}
}

func (rr *rawxRequest) checkChunkSize(chunkIn fileReader) error {
	if rr.chunk.size != chunkIn.size() && rr.chunk.compression == "off" {
		return errors.New(fmt.Sprintf(
			"File size (%d) different from recorded chunk size (%d)",
			chunkIn.size(), rr.chunk.size))
	}
	return nil
}

func (rr *rawxRequest) checkChunk() {
	chunkIn, err := rr.rawx.repo.get(rr.chunkID)
	if err != nil {
		rr.replyError("checkChunk()", err)
		return
	}
	defer chunkIn.Close()

	rr.chunk, err = loadAttr(rr, chunkIn, rr.chunkID)
	if err != nil {
		LogRequestDebug(rr, msgErrorAction("Getxattr()", err))
		rr.replyError("", err)
		return
	}

	// FIXME(jfs): generalize the check of chunkInfo
	if rr.chunk.ChunkHash == "" {
		rr.replyError("checkChunk()", errMissingXattr(defs.AttrNameChunkChecksum, nil))
		return
	}

	err = rr.checkChunkSize(chunkIn)
	if err != nil {
		rr.replyCode(http.StatusPreconditionFailed)
		return
	}

	if GetBool(rr.req.Header.Get(defs.HeaderNameCheckHash), false) {
		expected_hash := rr.req.Header.Get(defs.HeaderNameChunkChecksum)
		if expected_hash == "" {
			expected_hash = rr.chunk.ChunkHash
		}
		expected_hash = strings.ToUpper(expected_hash)

		var filter io.ReadCloser
		var in *io.LimitedReader
		in, filter, err = rr.getChunkReader(chunkIn, rr.chunk.size, rangeInfo{})
		if err != nil {
			LogRequestDebug(rr, msgErrorAction("getChunkReader()", err))
			rr.replyError("checkChunk()", err)
			return
		}
		if filter != nil {
			defer filter.Close()
		}
		var h hash.Hash
		if len(expected_hash) == 32 {
			h = md5.New()
		} else {
			h = blake3.New(32, nil)
		}
		if _, err = io.Copy(h, in); err == nil {
			actual_hash := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
			if expected_hash != actual_hash {
				LogRequestDebug(rr, msgErrorAction("hash comparison", nil))
				rr.replyCode(http.StatusPreconditionFailed)
				return
			}
		}
		if err != nil {
			// This special case is not in the main error handler, because
			// StatusPreconditionFailed only makes sense when verifying
			// chunk checksum, and it means "the checksum" does not match.
			// In case of "Input/output error", we consider the chunk is
			// corrupt, and we treat it the same way as above.
			if perr, ok := err.(*os.PathError); ok && perr.Err == syscall.EIO {
				LogRequestError(rr, msgErrorAction("hash computation", err))
				rr.replyCode(http.StatusPreconditionFailed)
			} else if serr, ok := err.(*os.SyscallError); ok && serr.Err == syscall.EIO {
				LogRequestError(rr, msgErrorAction("hash computation", err))
				rr.replyCode(http.StatusPreconditionFailed)
			} else {
				// An error is logged if we provide an "action" (1st param)
				rr.replyError("hash computation", err)
				return
			}
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
	if headerRange == "" {
		return ri, nil
	}

	var range_start int64
	var range_end int64
	max_range_end := chunkSize - 1
	match := RangeRegex.FindStringSubmatch(headerRange)
	if match == nil {
		return ri, nil
	}
	if match[1] == "" {
		if match[2] == "" {
			// bytes=-
			return ri, nil
		}
		// bytes=-<suffix-length>
		suffix_length, _ := strconv.ParseInt(match[2], 10, 64)
		if suffix_length <= 0 {
			// No data to send
			return ri, errInvalidRange
		}
		range_start = chunkSize - suffix_length
		if range_start < 0 {
			range_start = 0
		}
		range_end = max_range_end
	} else {
		range_start, _ = strconv.ParseInt(match[1], 10, 64)
		if match[2] == "" {
			// bytes=<range-start>-
			if range_start > max_range_end {
				// Range start beyond the data
				return ri, errInvalidRange
			}
			range_end = max_range_end
		} else {
			// bytes=<range-start>-<range-end>
			range_end, _ = strconv.ParseInt(match[2], 10, 64)
			if range_start > range_end {
				// Range is reversed
				return ri, nil
			}
			if range_start > max_range_end {
				// Range start beyond the data
				return ri, errInvalidRange
			}
			if range_end > max_range_end {
				range_end = max_range_end
			}
		}
	}

	ri.offset = range_start
	ri.last = range_end
	ri.size = range_end - range_start + 1
	return ri, nil
}

func (rr *rawxRequest) downloadChunk() {
	inChunk, err := rr.rawx.repo.get(rr.chunkID)
	if err != nil {
		rr.replyError("downloadChunk()", err)
		return
	}
	defer inChunk.Close()

	if rr.chunk, err = loadAttr(rr, inChunk, rr.chunkID); err != nil {
		rr.replyError("downloadChunk()", err)
		return
	}

	err = rr.checkChunkSize(inChunk)
	if err != nil {
		logger.LogWarning("Won't serve chunk %s: %v", rr.chunkID, err)
		rr.replyCode(http.StatusPreconditionFailed)
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
		rr.replyError("downloadChunk()", err)
		return
	}

	in, filter, err = rr.getChunkReader(inChunk, rr.chunk.size, rangeInf)
	if filter != nil {
		defer filter.Close()
	}
	if err != nil {
		rr.replyError("downloadChunk()", err)
		return
	}

	// Prepare the headers of the reply
	headers := rr.rep.Header()
	rr.chunk.fillHeaders(headers)
	if !rangeInf.isVoid() {
		headers.Set("Content-Range", packRangeHeader(rangeInf.offset, rangeInf.last, rr.chunk.size))
		headers.Set("Content-Length", strconv.FormatUint(uint64(rangeInf.size), 10))
		rr.replyCode(http.StatusPartialContent)
	} else {
		headers.Set("Content-Length", strconv.FormatUint(uint64(rr.chunk.size), 10))
		rr.replyCode(http.StatusOK)
	}

	// Now transmit the clear data to the client
	rr.TTFB = time.Since(rr.startTime)
	nb, err := io.Copy(rr.rep, in)
	rr.bytesOut = rr.bytesOut + uint64(nb)
	if err != nil {
		LogRequestError(rr, msgErrorAction("Write()", err))
	}
}

func (rr *rawxRequest) getChunkReader(inChunk fileReader, cs int64, ri rangeInfo) (in *io.LimitedReader, filter io.ReadCloser, err error) {
	// !!!(jfs): we do not manage requests on multiple ranges
	// TODO(jfs): is a multiple range is encountered, we should follow the norm
	// that allows us to answer a "200 OK" with the complete content.
	switch rr.chunk.compression {
	case defs.CompressionZlib:
		filter, err = zlib.NewReader(inChunk.File())
	case defs.CompressionLzw:
		filter = lzw.NewReader(inChunk.File(), lzw.MSB, 8)
	case defs.CompressionDeflate:
		filter = flate.NewReader(inChunk.File())
	case "", defs.CompressionOff:
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
	var err error

	if NotifAllowed {
		rr.chunk = chunkInfo{}
		rr.chunk.ChunkID = rr.chunkID
		rr.chunk.ContainerID = rr.req.Header.Get(defs.HeaderNameContainerID)
		rr.chunk.ContentID = rr.req.Header.Get(defs.HeaderNameContentID)

		if rr.chunk.ContainerID == "" || rr.chunk.ContentID == "" {
			tmp := xattrBufferPool.Acquire()
			defer xattrBufferPool.Release(tmp)

			getter := func(name, key string) (string, error) {
				nb, err := rr.rawx.repo.getAttr(name, key, tmp)
				if nb <= 0 || err != nil {
					return "", err
				} else {
					return string(tmp[:nb]), err
				}
			}

			// Load only the fullpath in an attempt to spare syscalls
			rr.chunk, err = loadFullPath(getter, rr.chunkID)
			if err != nil {
				rr.replyError("removeChunk()", err)
				return
			}
		}
	}

	err = rr.rawx.repo.del(rr.chunkID)
	if err != nil {
		rr.replyError("removeChunk()", err)
	} else {
		rr.replyCode(http.StatusNoContent)
		if NotifAllowed {
			rr.rawx.notifier.NotifyDel(rr.reqid, rr.chunk)
		}
	}
}

func (rr *rawxRequest) serveChunk() {
	// 24 digits (96 bits) seems reasonable to avoid collisions.
	// TODO(FVE): make the minimum and maximum configurable
	if !utils.IsHexaString(rr.req.URL.Path[1:], 24, 64) {
		rr.replyError("", errInvalidChunkID)
		return
	}

	rr.chunkID = strings.ToUpper(rr.req.URL.Path[1:])
	shouldLogPath := false

	var spent uint64
	var ttfb uint64
	if !rr.rawx.isIOok() {
		rr.replyIoError(rr.rawx)
	} else {
		switch rr.req.Method {
		case "GET":
			shouldLogPath = true
			concurrency.CountGET(func() {
				if err := rr.drain(); err != nil {
					rr.replyError("", err)
				} else {
					rr.downloadChunk()
				}
			})
		case "PUT":
			shouldLogPath = true
			concurrency.CountPUT(func() {
				rr.uploadChunk()
			})
		case "DELETE":
			concurrency.CountDEL(func() {
				if err := rr.drain(); err != nil {
					rr.replyError("", err)
				} else {
					rr.removeChunk()
				}
			})
		case "HEAD":
			if err := rr.drain(); err != nil {
				rr.replyError("", err)
			} else {
				rr.checkChunk()
			}
		case "COPY":
			if err := rr.drain(); err != nil {
				rr.replyError("", err)
			} else {
				rr.copyChunk()
			}
		case "POST":
			if err := rr.drain(); err != nil {
				rr.replyError("", err)
			} else {
				rr.updateChunk()
			}
		default:
			if err := rr.drain(); err != nil {
				rr.replyError("", err)
			} else {
				rr.replyCode(http.StatusMethodNotAllowed)
			}
		}
	}
	spent, ttfb = IncrementStatReqMethod(rr)

	if shouldAccessLog(rr.status, rr.req.Method) {
		evt := logger.AccessLogEvent{
			Status:      rr.status,
			TimeSpent:   spent,
			BytesIn:     rr.bytesIn,
			BytesOut:    rr.bytesOut,
			Method:      rr.req.Method,
			Local:       rr.req.Host,
			Peer:        rr.req.RemoteAddr,
			Path:        rr.req.URL.Path,
			ReqId:       rr.reqid,
			TLS:         rr.req.TLS != nil,
			TTFB:        ttfb,
			LogPath:     shouldLogPath,
			Concurrency: concurrency.GetConcurrency(),
		}
		if shouldLogPath {
			populateLongFields(&evt, rr)
		}
		logger.LogHttp(evt)
	}
}

func populateLongFields(evt *logger.AccessLogEvent, rr *rawxRequest) {
	fullPath := rr.req.Header.Get(defs.HeaderNameFullpath)
	if fullPath != "" {
		tokens := strings.SplitN(fullPath, "/", 3)
		if len(tokens) >= 1 {
			evt.Account = tokens[0]
		}
		if len(tokens) >= 2 {
			evt.Bucket = strings.TrimSuffix(tokens[1], defs.BucketSegmentsSuffix)
		}
	}
}

func packRangeHeader(start, last, size int64) string {
	sb := strings.Builder{}
	sb.WriteString("bytes ")
	sb.WriteString(utils.Itoa64(start))
	sb.WriteRune('-')
	sb.WriteString(utils.Itoa64(last))
	sb.WriteRune('/')
	sb.WriteString(utils.Itoa64(size))
	return sb.String()
}

func msgErrorAction(action string, err error) string {
	sb := strings.Builder{}
	sb.WriteString(action)
	if err == nil {
		sb.WriteString(" error (nil)")
	} else {
		sb.WriteString(" error (")
		sb.WriteString(err.Error())
		sb.WriteString(")")
	}
	return sb.String()
}

func statusOk(status int) bool {
	return status >= 200 && status < 300
}

func shouldAccessLog(status int, method string) bool {
	if !statusOk(status) || logger.IsVerbose() {
		return true
	}

	switch method {
	case "GET", "HEAD":
		return logger.AccessLogGet
	case "PUT":
		return logger.AccessLogPut
	case "POST":
		return logger.AccessLogPost
	case "DELETE":
		return logger.AccessLogDel
	default:
		return true
	}
}
