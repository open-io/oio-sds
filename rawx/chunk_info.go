// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2021-2022 OVH SAS
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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type chunkInfo struct {
	ContentFullpath    string `json:"full_path,omitempty"`
	ContainerID        string `json:"container_id,omitempty"`
	ContentPath        string `json:"content_path,omitempty"`
	ContentVersion     string `json:"content_version,omitempty"`
	ContentID          string `json:"content_id,omitempty"`
	ContentChunkMethod string `json:"content_chunk_method,omitempty"`
	ContentStgPol      string `json:"content_storage_policy,omitempty"`
	MetachunkHash      string `json:"metachunk_hash,omitempty"`
	MetachunkSize      string `json:"metachunk_size,omitempty"`
	ChunkID            string `json:"chunk_id,omitempty"`
	ChunkPosition      string `json:"chunk_position,omitempty"`
	ChunkHash          string `json:"chunk_hash,omitempty"`
	ChunkHashAlgo      string `json:"chunk_hash_algo,omitempty"`
	ChunkSize          string `json:"chunk_size,omitempty"`
	OioVersion         string `json:"oio_version,omitempty"`

	compression         string
	mtime               time.Time
	size                int64
	nonOptimalPlacement bool // default to false
}

func cidFromName(account, container string) string {
	h := sha256.New()
	h.Write([]byte(account))
	h.Write([]byte{0})
	h.Write([]byte(container))
	return strings.ToUpper(hex.EncodeToString(h.Sum(nil)))
}

type detailedAttr struct {
	key string
	ptr *string
}

// parseChunkMethod parses a "chunk method" string into a type and a map
// of string parameters.
func parseChunkMethod(chunkMethodStr string) (string, map[string]string) {
	splitems := strings.SplitN(chunkMethodStr, "/", 2)
	chunkMethodParams := make(map[string]string)
	chunkMethodType := splitems[0]
	for _, kv_str := range strings.Split(splitems[1], ",") {
		kv := strings.SplitN(kv_str, "=", 2)
		if len(kv) == 2 {
			chunkMethodParams[kv[0]] = kv[1]
		} else {
			LogWarning("Ignoring misformatted chunk method parameter: %s", kv_str)
		}
	}

	return chunkMethodType, chunkMethodParams
}

// serializeChunkMethod creates a "chunk method" string from a type and a map
// of string parameters.
func serializeChunkMethod(chunkMethodType string, params map[string]string) string {
	out := strings.Builder{}
	out.WriteString(chunkMethodType)
	out.WriteRune('/')
	first := true
	for key, value := range params {
		if !first {
			out.WriteRune(',')
		} else {
			first = false
		}
		out.WriteString(key)
		out.WriteRune('=')
		out.WriteString(value)
	}
	return out.String()
}

func (chunk chunkInfo) saveContentFullpathAttr(out decorable) error {
	if chunk.ChunkID == "" || chunk.ContentFullpath == "" {
		return errors.New("Missing chunk ID or fullpath")
	}

	return out.setAttr(xattrKey(chunk.ChunkID), []byte(chunk.ContentFullpath))
}

func (chunk chunkInfo) saveAttr(out decorable) error {
	setAttr := func(k, v string) error {
		if v == "" {
			return nil
		}
		return out.setAttr(k, []byte(v))
	}

	if err := chunk.saveContentFullpathAttr(out); err != nil {
		return err
	}

	var detailedAttrs = []detailedAttr{
		{AttrNameMetachunkChecksum, &chunk.MetachunkHash},
		{AttrNameMetachunkSize, &chunk.MetachunkSize},
		{AttrNameChunkChecksum, &chunk.ChunkHash},
		{AttrNameChunkSize, &chunk.ChunkSize},
		{AttrNameChunkPosition, &chunk.ChunkPosition},
		{AttrNameContentChunkMethod, &chunk.ContentChunkMethod},
		{AttrNameContentStgPol, &chunk.ContentStgPol},
		{AttrNameOioVersion, &chunk.OioVersion},
		{AttrNameCompression, &chunk.compression},
	}
	for _, hs := range detailedAttrs {
		if err := setAttr(hs.key, *(hs.ptr)); err != nil {
			return err
		}
	}

	// TODO(jfs): save the compression status
	return nil
}

func loadFullPath(getter func(string, string) (string, error), chunkID string) (chunkInfo, error) {
	var chunk chunkInfo

	chunk.ChunkID = chunkID

	fp, err := getter(chunkID, xattrKey(chunkID))
	if err == nil {
		// New chunk
		fpTokens := strings.Split(fp, "/")
		if len(fpTokens) == 5 {
			chunk.ContentFullpath = fp
			account, _ := url.PathUnescape(fpTokens[0])
			container, _ := url.PathUnescape(fpTokens[1])
			chunk.ContainerID = cidFromName(account, container)
			chunk.ContentPath, _ = url.PathUnescape(fpTokens[2])
			chunk.ContentVersion, _ = url.PathUnescape(fpTokens[3])
			chunk.ContentID, _ = url.PathUnescape(fpTokens[4])
		} else {
			return chunk, errors.New("Invalid fullpath")
		}
	} else {
		if err != syscall.ENODATA {
			return chunk, err
		}
		chunk.ContainerID, err = getter(chunkID, AttrNameContainerID)
		if err == nil {
			chunk.ContentPath, err = getter(chunkID, AttrNameContentPath)
			if err == nil {
				chunk.ContentVersion, err = getter(chunkID, AttrNameContentVersion)
				if err == nil {
					chunk.ContentID, err = getter(chunkID, AttrNameContentID)
				}
			}
		}
		if err != nil && err != syscall.ENODATA {
			return chunk, err
		}
	}

	return chunk, nil
}

func loadAttr(rr *rawxRequest, inChunk fileReader, chunkID string) (chunkInfo, error) {
	var chunk chunkInfo

	buf := xattrBufferPool.Acquire()
	defer xattrBufferPool.Release(buf)

	getAttr := func(k string) (string, error) {
		l, err := inChunk.getAttr(k, buf)
		if l <= 0 || err != nil {
			return "", err
		} else {
			return string(buf[:l]), nil
		}
	}

	/* keep AttrNameContentStgPol above AttrNameMetachunkChecksum and AttrNameMetachunkSize */
	var detailedAttrs = []detailedAttr{
		{AttrNameContentChunkMethod, &chunk.ContentChunkMethod},
		{AttrNameContentStgPol, &chunk.ContentStgPol},
		{AttrNameMetachunkChecksum, &chunk.MetachunkHash},
		{AttrNameMetachunkSize, &chunk.MetachunkSize},
		{AttrNameChunkPosition, &chunk.ChunkPosition},
		{AttrNameChunkChecksum, &chunk.ChunkHash},
		{AttrNameChunkSize, &chunk.ChunkSize},
		{AttrNameOioVersion, &chunk.OioVersion},
		{AttrNameCompression, &chunk.compression},
	}

	contentFullpath, err := getAttr(xattrKey(chunkID))
	if err == nil {
		// New chunk
		fullpath := strings.Split(contentFullpath, "/")
		if len(fullpath) == 5 {
			chunk.ContentFullpath = contentFullpath
			account, _ := url.PathUnescape(fullpath[0])
			container, _ := url.PathUnescape(fullpath[1])
			chunk.ContainerID = cidFromName(account, container)
			chunk.ContentPath, _ = url.PathUnescape(fullpath[2])
			chunk.ContentVersion, _ = url.PathUnescape(fullpath[3])
			chunk.ContentID, _ = url.PathUnescape(fullpath[4])
		} else {
			return chunk, errors.New("Invalid fullpath")
		}
	} else {
		if err != syscall.ENODATA {
			return chunk, err
		}
		// Old chunk
		_chunkID, err := getAttr(AttrNameChunkID)
		if err != nil {
			if err == syscall.ENODATA {
				LogRequestWarning(rr,
					msgMissingXattr(chunkID, AttrNameChunkID, err))
			} else {
				return chunk, err
			}
		}
		if _chunkID == chunkID {
			detailedAttrs = append(detailedAttrs,
				detailedAttr{AttrNameContainerID, &chunk.ContainerID},
				detailedAttr{AttrNameContentPath, &chunk.ContentPath},
				detailedAttr{AttrNameContentVersion, &chunk.ContentVersion},
				detailedAttr{AttrNameContentID, &chunk.ContentID})
		}
	}
	chunk.ChunkID = chunkID

	for _, hs := range detailedAttrs {
		*(hs.ptr), err = getAttr(hs.key)
		if err != nil {
			if err == syscall.ENODATA {
				/* for storage_policy other than EC, don't print error for missing MetachunkSize and MetachunkHash */
				if !strings.HasPrefix(chunk.ContentChunkMethod, ECMethodPrefix) &&
					(hs.key == AttrNameMetachunkChecksum || hs.key == AttrNameMetachunkSize) {
					continue
				}
				/* Compression is not mandatory, don't print error for missing Compression attr */
				if hs.key == AttrNameCompression {
					continue
				}
				LogRequestWarning(rr, msgMissingXattr(chunkID, hs.key, err))
			} else {
				return chunk, err
			}
		}
	}

	chunk.mtime = inChunk.mtime()
	chunk.size, err = strconv.ParseInt(chunk.ChunkSize, 10, 63)
	if err != nil {
		err = errMissingXattr(AttrNameChunkSize, err)
	}
	if chunk.ContentChunkMethod != "" {
		chunkMethodType, params := parseChunkMethod(chunk.ContentChunkMethod)
		algo, found := params["cca"] // cca = Chunk Checksum Algo
		if found {
			chunk.ChunkHashAlgo = algo
		} else {
			if len(chunk.ChunkHash) == 32 {
				chunk.ChunkHashAlgo = "md5" // old default value
			} else {
				chunk.ChunkHashAlgo = "blake3"
			}
			params["cca"] = chunk.ChunkHashAlgo
			chunk.ContentChunkMethod = serializeChunkMethod(chunkMethodType, params)
		}
	}
	return chunk, nil
}

func msgMissingXattr(chunk, key string, cause error) string {
	return msgErrorAction(key, cause)
}

func errMissingXattr(key string, cause error) error {
	sb := strings.Builder{}
	sb.WriteString(key)
	sb.WriteString(" missing")
	if cause != nil {
		sb.WriteRune(':')
		sb.WriteRune(' ')
		sb.WriteString(cause.Error())
	}
	return errors.New(sb.String())
}

// Check and load the content fullpath of the chunk.
func (chunk *chunkInfo) retrieveContentFullpathHeader(headers *http.Header) error {
	headerFullpath := headers.Get(HeaderNameFullpath)
	if headerFullpath == "" {
		return errMissingHeader
	}
	fullpath := strings.Split(headerFullpath, "/")
	if len(fullpath) != 5 {
		return errInvalidHeader
	}

	account, err := url.PathUnescape(fullpath[0])
	if err != nil || account == "" {
		return errInvalidHeader
	}
	container, err := url.PathUnescape(fullpath[1])
	if err != nil || container == "" {
		return errInvalidHeader
	}
	containerID := cidFromName(account, container)
	headerContainerID := headers.Get(HeaderNameContainerID)
	if headerContainerID != "" {
		if !strings.EqualFold(containerID, headerContainerID) {
			return errInvalidHeader
		}
	}
	chunk.ContainerID = containerID

	path, err := url.PathUnescape(fullpath[2])
	if err != nil || path == "" {
		return errInvalidHeader
	}
	headerPath := headers.Get(HeaderNameContentPath)
	if headerPath != "" {
		headerPath, err = url.PathUnescape(headerPath)
		if err != nil || headerPath != path {
			return errInvalidHeader
		}
	}
	chunk.ContentPath = path

	version, err := url.PathUnescape(fullpath[3])
	if err != nil {
		return errInvalidHeader
	}
	if _, err := strconv.ParseInt(version, 10, 64); err != nil {
		return errInvalidHeader
	}
	headerVersion := headers.Get(HeaderNameContentVersion)
	if headerVersion != "" && headerVersion != version {
		return errInvalidHeader
	}
	chunk.ContentVersion = version

	contentID, err := url.PathUnescape(fullpath[4])
	if err != nil || !isHexaString(contentID, 0, 64) {
		return errInvalidHeader
	}
	headerContentID := headers.Get(HeaderNameContentID)
	if headerContentID == "" && contentID == "" {
		return errMissingHeader
	}
	if headerContentID != "" && !strings.EqualFold(headerContentID, contentID) {
		return errInvalidHeader
	}
	chunk.ContentID = strings.ToUpper(contentID)

	beginContentID := strings.LastIndex(headerFullpath, "/") + 1
	chunk.ContentFullpath = headerFullpath[:beginContentID] + chunk.ContentID
	return nil
}

// Check and load the content fullpath of the chunk.
func retrieveDestinationHeader(headers *http.Header, rawx *rawxService, srcChunkID string) (chunkInfo, error) {
	var chunk chunkInfo

	destination := headers.Get("Destination")
	if destination == "" {
		return chunk, errMissingHeader
	}
	dstURL, err := url.ParseRequestURI(destination)
	if err != nil {
		return chunk, errInvalidHeader
	}
	if dstURL.Host != rawx.id && dstURL.Host != rawx.url {
		return chunk, os.ErrPermission
	}
	chunk.ChunkID = filepath.Base(filepath.Clean(dstURL.Path))
	if !isHexaString(chunk.ChunkID, 24, 64) {
		LogWarning("%s did not parse as hexadecimal string", chunk.ChunkID)
		return chunk, errInvalidHeader
	}
	chunk.ChunkID = strings.ToUpper(chunk.ChunkID)
	if chunk.ChunkID == srcChunkID {
		return chunk, os.ErrPermission
	}
	return chunk, nil
}

// Check and load the info of the chunk.
func retrieveHeaders(headers *http.Header, chunkID string) (chunkInfo, error) {
	var chunk chunkInfo

	chunk.ContentStgPol = headers.Get(HeaderNameContentStgPol)
	if chunk.ContentStgPol == "" {
		return chunk, errMissingHeader
	}

	chunk.ContentChunkMethod = headers.Get(HeaderNameContentChunkMethod)
	if chunk.ContentChunkMethod == "" {
		return chunk, errMissingHeader
	}
	chunkMethodType, chunkParams := parseChunkMethod(chunk.ContentChunkMethod)
	chunk.ChunkHashAlgo = chunkParams["cca"] // cca = Chunk Checksum Algo
	if chunk.ChunkHashAlgo == "" {
		// md5 was the default before we saved the algorithm name
		chunk.ChunkHashAlgo = "md5"
		chunkParams["cca"] = "md5"
		chunk.ContentChunkMethod = serializeChunkMethod(chunkMethodType, chunkParams)
	}

	chunkIDHeader := headers.Get(HeaderNameChunkID)
	if chunkIDHeader != "" && !strings.EqualFold(chunkIDHeader, chunkID) {
		return chunk, errInvalidHeader
	}
	chunk.ChunkID = strings.ToUpper(chunkID)
	chunk.ChunkPosition = headers.Get(HeaderNameChunkPosition)
	if chunk.ChunkPosition == "" {
		return chunk, errMissingHeader
	}

	chunk.MetachunkHash = headers.Get(HeaderNameMetachunkChecksum)
	if chunk.MetachunkHash != "" {
		if !isHexaString(chunk.MetachunkHash, 0, 64) {
			return chunk, errInvalidHeader
		}
		chunk.MetachunkHash = strings.ToUpper(chunk.MetachunkHash)
	}
	chunk.MetachunkSize = headers.Get(HeaderNameMetachunkSize)
	if chunk.MetachunkSize != "" {
		if _, err := strconv.ParseInt(chunk.MetachunkSize, 10, 64); err != nil {
			return chunk, errInvalidHeader
		}
	}

	chunk.ChunkHash = headers.Get(HeaderNameChunkChecksum)
	if chunk.ChunkHash != "" {
		if !isHexaString(chunk.ChunkHash, 0, 64) {
			return chunk, errInvalidHeader
		}
		chunk.ChunkHash = strings.ToUpper(chunk.ChunkHash)
	}
	chunk.ChunkSize = headers.Get(HeaderNameChunkSize)
	if chunk.ChunkSize != "" {
		if _, err := strconv.ParseInt(chunk.ChunkSize, 10, 64); err != nil {
			return chunk, errInvalidHeader
		}
	}
	if GetBool(headers.Get(HeaderNameNonOptimalPlacement), false) {
		chunk.nonOptimalPlacement = true
	}

	chunk.OioVersion = OioVersion
	err := chunk.retrieveContentFullpathHeader(headers)
	return chunk, err
}

// Check and load the checksum and the size of the chunk and the metachunk
func (chunk *chunkInfo) patchWithTrailers(trailers *http.Header, ul uploadInfo) error {
	trailerMetachunkHash := trailers.Get(HeaderNameMetachunkChecksum)
	if trailerMetachunkHash != "" {
		chunk.MetachunkHash = trailerMetachunkHash
		if chunk.MetachunkHash != "" {
			if !isHexaString(chunk.MetachunkHash, 0, 64) {
				return errInvalidHeader
			}
			chunk.MetachunkHash = strings.ToUpper(chunk.MetachunkHash)
		}
	}
	trailerMetachunkSize := trailers.Get(HeaderNameMetachunkSize)
	if trailerMetachunkSize != "" {
		chunk.MetachunkSize = trailerMetachunkSize
		if chunk.MetachunkSize != "" {
			if _, err := strconv.ParseInt(chunk.MetachunkSize, 10, 64); err != nil {
				return errInvalidHeader
			}
		}
	}
	if strings.HasPrefix(chunk.ContentChunkMethod, ECMethodPrefix) {
		if chunk.MetachunkHash == "" {
			return errMissingHeader
		}
		if chunk.MetachunkSize == "" {
			return errMissingHeader
		}
	}

	trailerChunkHash := trailers.Get(HeaderNameChunkChecksum)
	if trailerChunkHash != "" {
		chunk.ChunkHash = strings.ToUpper(trailerChunkHash)
	}
	if chunk.ChunkHash != "" {
		if !strings.EqualFold(chunk.ChunkHash, ul.hash) {
			return errInvalidHeader
		}
	} else {
		chunk.ChunkHash = ul.hash
	}
	trailerChunkSize := trailers.Get(HeaderNameChunkSize)
	if trailerChunkSize != "" {
		chunk.ChunkSize = trailerChunkSize
	}
	if chunk.ChunkSize != "" {
		if chunkSize, err := strconv.ParseInt(chunk.ChunkSize, 10, 64); err != nil ||
			chunkSize != ul.length {
			return errInvalidHeader
		}
	} else {
		chunk.ChunkSize = strconv.FormatInt(ul.length, 10)
	}

	return nil
}

func setHeader(headers http.Header, k, v string) {
	if len(v) > 0 {
		headers.Set(k, v)
	}
}

// Fill the headers of the reply with the attributes of the chunk
func (chunk chunkInfo) fillHeaders(headers http.Header) {
	setHeader(headers, HeaderNameFullpath, chunk.ContentFullpath)
	setHeader(headers, HeaderNameContainerID, chunk.ContainerID)
	setHeader(headers, HeaderNameContentPath, url.PathEscape(chunk.ContentPath))
	setHeader(headers, HeaderNameContentVersion, chunk.ContentVersion)
	setHeader(headers, HeaderNameContentID, chunk.ContentID)
	setHeader(headers, HeaderNameContentStgPol, chunk.ContentStgPol)
	setHeader(headers, HeaderNameContentChunkMethod, chunk.ContentChunkMethod)
	setHeader(headers, HeaderNameMetachunkChecksum, chunk.MetachunkHash)
	setHeader(headers, HeaderNameChunkID, chunk.ChunkID)
	setHeader(headers, HeaderNameMetachunkSize, chunk.MetachunkSize)
	setHeader(headers, HeaderNameChunkPosition, chunk.ChunkPosition)
	setHeader(headers, HeaderNameChunkChecksum, chunk.ChunkHash)
	setHeader(headers, HeaderNameChunkSize, chunk.ChunkSize)
	setHeader(headers, HeaderNameXattrVersion, chunk.OioVersion)
	setHeader(headers, "Last-Modified", chunk.mtime.Format(time.RFC1123))
}

// Fill the headers of the reply with the chunk info calculated by the rawx
func (chunk chunkInfo) fillHeadersLight(headers http.Header) {
	setHeader(headers, HeaderNameChunkChecksum, chunk.ChunkHash)
	setHeader(headers, HeaderNameChunkSize, chunk.ChunkSize)
	setHeader(headers, HeaderNameXattrVersion, chunk.OioVersion)
}
