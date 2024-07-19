// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2021-2024 OVH SAS
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
	"bytes"
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

	"openio-sds/rawx/defs"
	"openio-sds/rawx/utils"
)

type chunkInfo struct {
	ContentFullpath    string            `json:"full_path,omitempty"`
	ContainerID        string            `json:"container_id,omitempty"`
	ContentPath        string            `json:"content_path,omitempty"`
	ContentVersion     string            `json:"content_version,omitempty"`
	ContentID          string            `json:"content_id,omitempty"`
	ContentChunkMethod string            `json:"content_chunk_method,omitempty"`
	ContentStgPol      string            `json:"content_storage_policy,omitempty"`
	MetachunkHash      string            `json:"metachunk_hash,omitempty"`
	MetachunkSize      string            `json:"metachunk_size,omitempty"`
	ChunkID            string            `json:"chunk_id,omitempty"`
	ChunkPosition      string            `json:"chunk_position,omitempty"`
	ChunkHash          string            `json:"chunk_hash,omitempty"`
	ChunkHashAlgo      string            `json:"chunk_hash_algo,omitempty"`
	ChunkSize          string            `json:"chunk_size,omitempty"`
	ExtMeta            map[string]string `json:"ext_meta,omitempty"`

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

func (chunk chunkInfo) saveExtMetaAttr(out decorable) error {
	for k, v := range chunk.ExtMeta {
		attrKey := "user.oio.ext." + k
		if err := out.setAttr(attrKey, []byte(v)); err != nil {
			return err
		}
	}
	return nil
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
		{defs.AttrNameMetachunkChecksum, &chunk.MetachunkHash},
		{defs.AttrNameMetachunkSize, &chunk.MetachunkSize},
		{defs.AttrNameChunkChecksum, &chunk.ChunkHash},
		{defs.AttrNameChunkSize, &chunk.ChunkSize},
		{defs.AttrNameChunkPosition, &chunk.ChunkPosition},
		{defs.AttrNameContentChunkMethod, &chunk.ContentChunkMethod},
		{defs.AttrNameContentStgPol, &chunk.ContentStgPol},
		{defs.AttrNameCompression, &chunk.compression},
	}
	for _, hs := range detailedAttrs {
		if err := setAttr(hs.key, *(hs.ptr)); err != nil {
			return err
		}
	}

	if err := chunk.saveExtMetaAttr(out); err != nil {
		return err
	}

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
		chunk.ContainerID, err = getter(chunkID, defs.AttrNameContainerID)
		if err == nil {
			chunk.ContentPath, err = getter(chunkID, defs.AttrNameContentPath)
			if err == nil {
				chunk.ContentVersion, err = getter(chunkID, defs.AttrNameContentVersion)
				if err == nil {
					chunk.ContentID, err = getter(chunkID, defs.AttrNameContentID)
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
	attrListBuf := xattrBufferPool.Acquire()
	defer xattrBufferPool.Release(attrListBuf)

	getAttr := func(k string) (string, error) {
		l, err := inChunk.getAttr(k, buf)
		if l <= 0 || err != nil {
			return "", err
		} else {
			return string(buf[:l]), nil
		}
	}

	/* form the list of extended attributes, get attribute that start with prefix */
	getExtMeta := func(listBuffer []byte) (map[string]string, error) {
		prefix := "user.oio.ext."
		res := make(map[string]string)
		var err error
		for i := 0; i < len(listBuffer); i++ {
			// attributes names are separated by null bytes
			if listBuffer[i] == byte(0) {
				attrKey := listBuffer[:i]
				extMetaKey, hasPrefix := bytes.CutPrefix(attrKey, []byte(prefix))
				if hasPrefix {
					extMetaAttr, err := getAttr(string(attrKey))
					if err == nil {
						res[string(extMetaKey)] = extMetaAttr
					}
				}
				listBuffer = listBuffer[i+1:]
				i = -1
			}
		}
		return res, err
	}

	/* keep AttrNameContentStgPol above AttrNameMetachunkChecksum and AttrNameMetachunkSize */
	var detailedAttrs = []detailedAttr{
		{defs.AttrNameContentChunkMethod, &chunk.ContentChunkMethod},
		{defs.AttrNameContentStgPol, &chunk.ContentStgPol},
		{defs.AttrNameMetachunkChecksum, &chunk.MetachunkHash},
		{defs.AttrNameMetachunkSize, &chunk.MetachunkSize},
		{defs.AttrNameChunkPosition, &chunk.ChunkPosition},
		{defs.AttrNameChunkChecksum, &chunk.ChunkHash},
		{defs.AttrNameChunkSize, &chunk.ChunkSize},
		{defs.AttrNameCompression, &chunk.compression},
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
		_chunkID, err := getAttr(defs.AttrNameChunkID)
		if err != nil {
			if err == syscall.ENODATA {
				LogRequestWarning(rr,
					msgMissingXattr(chunkID, defs.AttrNameChunkID, err))
			} else {
				return chunk, err
			}
		}
		if _chunkID == chunkID {
			detailedAttrs = append(detailedAttrs,
				detailedAttr{defs.AttrNameContainerID, &chunk.ContainerID},
				detailedAttr{defs.AttrNameContentPath, &chunk.ContentPath},
				detailedAttr{defs.AttrNameContentVersion, &chunk.ContentVersion},
				detailedAttr{defs.AttrNameContentID, &chunk.ContentID})
		}
	}
	chunk.ChunkID = chunkID

	for _, hs := range detailedAttrs {
		*(hs.ptr), err = getAttr(hs.key)
		if err != nil {
			if err == syscall.ENODATA {
				/* for storage_policy other than EC, don't print error for missing MetachunkSize and MetachunkHash */
				if !strings.HasPrefix(chunk.ContentChunkMethod, defs.ECMethodPrefix) &&
					(hs.key == defs.AttrNameMetachunkChecksum || hs.key == defs.AttrNameMetachunkSize) {
					continue
				}
				/* Compression is not mandatory, don't print error for missing Compression attr */
				if hs.key == defs.AttrNameCompression {
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
		err = errMissingXattr(defs.AttrNameChunkSize, err)
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

	chunk.ExtMeta = make(map[string]string)

	/* To avoid calling syscall Listxattr twice, first call with buffer already
	* allocated, if its size is not sufficient, allocate a new buffer and call
	* listAttr again. */
	size, err := inChunk.listAttr(attrListBuf)
	if size < len(attrListBuf) {
		chunk.ExtMeta, err = getExtMeta(attrListBuf)
	} else {
		// buffer is to small
		attributes := make([]byte, size)
		_, err = inChunk.listAttr(attributes)
		chunk.ExtMeta, err = getExtMeta(attributes)
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
	headerFullpath := headers.Get(defs.HeaderNameFullpath)
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
	headerContainerID := headers.Get(defs.HeaderNameContainerID)
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
	headerPath := headers.Get(defs.HeaderNameContentPath)
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
	headerVersion := headers.Get(defs.HeaderNameContentVersion)
	if headerVersion != "" && headerVersion != version {
		return errInvalidHeader
	}
	chunk.ContentVersion = version

	contentID, err := url.PathUnescape(fullpath[4])
	if err != nil || !utils.IsHexaString(contentID, 0, 64) {
		return errInvalidHeader
	}
	headerContentID := headers.Get(defs.HeaderNameContentID)
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
	if !utils.IsHexaString(chunk.ChunkID, 24, 64) {
		LogWarning("%s did not parse as hexadecimal string", chunk.ChunkID)
		return chunk, errInvalidHeader
	}
	chunk.ChunkID = strings.ToUpper(chunk.ChunkID)
	if chunk.ChunkID == srcChunkID {
		return chunk, os.ErrPermission
	}
	return chunk, nil
}

// Retrieve headers for specific POST calls
func retrievePostHeaders(headers *http.Header, chunkID string) (chunkInfo, error) {
	var chunk chunkInfo
	if GetBool(headers.Get(defs.HeaderNameNonOptimalPlacement), false) {
		chunk.nonOptimalPlacement = true
	}
	chunk.loadExtHeaders(headers)
	return chunk, nil
}

func (chunk *chunkInfo) loadExtHeaders(headers *http.Header) {
	if chunk.ExtMeta == nil {
		chunk.ExtMeta = make(map[string]string)
	}
	for key, value := range *headers {
		if strippedKey, found := utils.HasPrefix(key, "X-Oio-Ext-"); found {
			chunk.ExtMeta[strippedKey], _ = url.PathUnescape(value[0])
		}
	}
}

// Check and load the info of the chunk.
func retrieveHeaders(headers *http.Header, chunkID string) (chunkInfo, error) {
	var chunk chunkInfo

	chunk.ContentStgPol = headers.Get(defs.HeaderNameContentStgPol)
	if chunk.ContentStgPol == "" {
		return chunk, errMissingHeader
	}

	chunk.ContentChunkMethod = headers.Get(defs.HeaderNameContentChunkMethod)
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

	chunkIDHeader := headers.Get(defs.HeaderNameChunkID)
	if chunkIDHeader != "" && !strings.EqualFold(chunkIDHeader, chunkID) {
		return chunk, errInvalidHeader
	}
	chunk.ChunkID = strings.ToUpper(chunkID)
	chunk.ChunkPosition = headers.Get(defs.HeaderNameChunkPosition)
	if chunk.ChunkPosition == "" {
		return chunk, errMissingHeader
	}

	chunk.MetachunkHash = headers.Get(defs.HeaderNameMetachunkChecksum)
	if chunk.MetachunkHash != "" {
		if !utils.IsHexaString(chunk.MetachunkHash, 0, 64) {
			return chunk, errInvalidHeader
		}
		chunk.MetachunkHash = strings.ToUpper(chunk.MetachunkHash)
	}
	chunk.MetachunkSize = headers.Get(defs.HeaderNameMetachunkSize)
	if chunk.MetachunkSize != "" {
		if _, err := strconv.ParseInt(chunk.MetachunkSize, 10, 64); err != nil {
			return chunk, errInvalidHeader
		}
	}

	chunk.ChunkHash = headers.Get(defs.HeaderNameChunkChecksum)
	if chunk.ChunkHash != "" {
		if !utils.IsHexaString(chunk.ChunkHash, 0, 64) {
			return chunk, errInvalidHeader
		}
		chunk.ChunkHash = strings.ToUpper(chunk.ChunkHash)
	}
	chunk.ChunkSize = headers.Get(defs.HeaderNameChunkSize)
	if chunk.ChunkSize != "" {
		if _, err := strconv.ParseInt(chunk.ChunkSize, 10, 64); err != nil {
			return chunk, errInvalidHeader
		}
	}
	if GetBool(headers.Get(defs.HeaderNameNonOptimalPlacement), false) {
		chunk.nonOptimalPlacement = true
	}

	if err := chunk.retrieveContentFullpathHeader(headers); err != nil {
		return chunk, err
	}

	chunk.loadExtHeaders(headers)

	return chunk, nil
}

// Check and load the checksum and the size of the chunk and the metachunk
func (chunk *chunkInfo) patchWithTrailers(trailers *http.Header, ul uploadInfo) error {
	trailerMetachunkHash := trailers.Get(defs.HeaderNameMetachunkChecksum)
	if trailerMetachunkHash != "" {
		chunk.MetachunkHash = trailerMetachunkHash
		if chunk.MetachunkHash != "" {
			if !utils.IsHexaString(chunk.MetachunkHash, 0, 64) {
				return errInvalidHeader
			}
			chunk.MetachunkHash = strings.ToUpper(chunk.MetachunkHash)
		}
	}
	trailerMetachunkSize := trailers.Get(defs.HeaderNameMetachunkSize)
	if trailerMetachunkSize != "" {
		chunk.MetachunkSize = trailerMetachunkSize
		if chunk.MetachunkSize != "" {
			if _, err := strconv.ParseInt(chunk.MetachunkSize, 10, 64); err != nil {
				return errInvalidHeader
			}
		}
	}
	if strings.HasPrefix(chunk.ContentChunkMethod, defs.ECMethodPrefix) {
		if chunk.MetachunkHash == "" {
			return errMissingHeader
		}
		if chunk.MetachunkSize == "" {
			return errMissingHeader
		}
	}

	trailerChunkHash := trailers.Get(defs.HeaderNameChunkChecksum)
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
	trailerChunkSize := trailers.Get(defs.HeaderNameChunkSize)
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

	chunk.loadExtHeaders(trailers)

	return nil
}

func setHeader(headers http.Header, k, v string) {
	if len(v) > 0 {
		headers.Set(k, v)
	}
}

// Fill the headers of the reply with the attributes of the chunk
func (chunk chunkInfo) fillHeaders(headers http.Header) {
	setHeader(headers, defs.HeaderNameFullpath, chunk.ContentFullpath)
	setHeader(headers, defs.HeaderNameContainerID, chunk.ContainerID)
	setHeader(headers, defs.HeaderNameContentPath, url.PathEscape(chunk.ContentPath))
	setHeader(headers, defs.HeaderNameContentVersion, chunk.ContentVersion)
	setHeader(headers, defs.HeaderNameContentID, chunk.ContentID)
	setHeader(headers, defs.HeaderNameContentStgPol, chunk.ContentStgPol)
	setHeader(headers, defs.HeaderNameContentChunkMethod, chunk.ContentChunkMethod)
	setHeader(headers, defs.HeaderNameMetachunkChecksum, chunk.MetachunkHash)
	setHeader(headers, defs.HeaderNameChunkID, chunk.ChunkID)
	setHeader(headers, defs.HeaderNameMetachunkSize, chunk.MetachunkSize)
	setHeader(headers, defs.HeaderNameChunkPosition, chunk.ChunkPosition)
	setHeader(headers, defs.HeaderNameChunkChecksum, chunk.ChunkHash)
	setHeader(headers, defs.HeaderNameChunkSize, chunk.ChunkSize)
	setHeader(headers, "Last-Modified", chunk.mtime.Format(time.RFC1123))
	if chunk.ExtMeta != nil {
		for key, value := range chunk.ExtMeta {
			setHeader(headers, "X-Oio-Ext-"+key, value)
		}
	}
}

// Fill the headers of the reply with the chunk info calculated by the rawx
func (chunk chunkInfo) fillHeadersLight(headers http.Header) {
	setHeader(headers, defs.HeaderNameChunkChecksum, chunk.ChunkHash)
	setHeader(headers, defs.HeaderNameChunkSize, chunk.ChunkSize)
}
