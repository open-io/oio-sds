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
)

type chunkInfo struct {
	contentFullpath    string
	containerID        string
	contentPath        string
	contentVersion     string
	contentID          string
	contentChunkMethod string
	contentStgPol      string
	metachunkHash      string
	metachunkSize      string
	chunkID            string
	chunkPosition      string
	chunkHash          string
	chunkSize          string
	oioVersion         string
}

const OioVersion = "4.2"

const (
	AttrNameFullPrefix = "user.oio.content.fullpath:"
)

const (
	AttrNameContentChunkMethod = "user.grid.content.chunk_method"
	AttrNameContentStgPol      = "user.grid.content.storage_policy"
	AttrNameMetachunkChecksum  = "user.grid.metachunk.hash"
	AttrNameMetachunkSize      = "user.grid.metachunk.size"
	AttrNameChunkPosition      = "user.grid.chunk.position"
	AttrNameChunkChecksum      = "user.grid.chunk.hash"
	AttrNameChunkSize          = "user.grid.chunk.size"
	AttrNameCompression        = "user.grid.compression"
	AttrNameOioVersion         = "user.grid.oio.version"
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
	HeaderNameXattrVersion       = "X-oio-Chunk-Meta-Oio-Version"
)

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

type detailedAttr struct {
	key string
	ptr *string
}

func (chunk *chunkInfo) saveContentFullpathAttr(out FileWriter) error {
	if chunk.chunkID == "" || chunk.contentFullpath == "" {
		return errors.New("Missing chunk ID or fullpath")
	}

	return out.SetAttr(AttrNameFullPrefix+chunk.chunkID, []byte(chunk.contentFullpath))
}

func (chunk *chunkInfo) saveAttr(out FileWriter) error {
	setAttr := func(k, v string) error {
		if v == "" {
			return nil
		}
		return out.SetAttr(k, []byte(v))
	}

	if err := chunk.saveContentFullpathAttr(out); err != nil {
		return err
	}

	var detailedAttrs = []detailedAttr{
		{AttrNameMetachunkChecksum, &chunk.metachunkHash},
		{AttrNameMetachunkSize, &chunk.metachunkSize},
		{AttrNameChunkChecksum, &chunk.chunkHash},
		{AttrNameChunkSize, &chunk.chunkSize},
		{AttrNameChunkPosition, &chunk.chunkPosition},
		{AttrNameContentChunkMethod, &chunk.contentChunkMethod},
		{AttrNameContentStgPol, &chunk.contentStgPol},
		{AttrNameOioVersion, &chunk.oioVersion},
	}
	for _, hs := range detailedAttrs {
		if err := setAttr(hs.key, *(hs.ptr)); err != nil {
			return err
		}
	}

	// TODO(jfs): save the compression status
	return nil
}

func (chunk *chunkInfo) loadAttr(inChunk FileReader, chunkID string) error {
	getAttr := func(k string) (string, error) {
		v, err := inChunk.GetAttr(k)
		return string(v), err
	}

	contentFullpath, err := getAttr(AttrNameFullPrefix + chunkID)
	if err != nil {
		return err
	}
	chunk.chunkID = chunkID
	fullpath := strings.Split(contentFullpath, "/")
	if len(fullpath) == 5 {
		chunk.contentFullpath = contentFullpath
		account, _ := url.PathUnescape(fullpath[0])
		container, _ := url.PathUnescape(fullpath[1])
		chunk.containerID = cidFromName(account, container)
		chunk.contentPath, _ = url.PathUnescape(fullpath[2])
		chunk.contentVersion, _ = url.PathUnescape(fullpath[3])
		chunk.contentID, _ = url.PathUnescape(fullpath[4])
	}

	var detailedAttrs = []detailedAttr{
		{AttrNameContentChunkMethod, &chunk.contentChunkMethod},
		{AttrNameContentStgPol, &chunk.contentStgPol},
		{AttrNameMetachunkChecksum, &chunk.metachunkHash},
		{AttrNameMetachunkSize, &chunk.metachunkSize},
		{AttrNameChunkPosition, &chunk.chunkPosition},
		{AttrNameChunkChecksum, &chunk.chunkHash},
		{AttrNameChunkSize, &chunk.chunkSize},
		{AttrNameOioVersion, &chunk.oioVersion},
	}
	for _, hs := range detailedAttrs {
		value, err := getAttr(hs.key)
		if err != nil && err != syscall.ENODATA {
			return err
		}
		*(hs.ptr) = value
	}

	return nil
}

// Check and load the content fullpath of the chunk.
func (chunk *chunkInfo) retrieveContentFullpathHeader(headers *http.Header) error {
	headerFullpath := headers.Get(HeaderNameFullpath)
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
	headerContainerID := headers.Get(HeaderNameContainerID)
	if headerContainerID != "" {
		if err != nil || !strings.EqualFold(containerID, headerContainerID) {
			return returnError(ErrInvalidHeader, HeaderNameContainerID)
		}
	}
	chunk.containerID = containerID

	path, err := url.PathUnescape(fullpath[2])
	if err != nil || path == "" {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	headerPath := headers.Get(HeaderNameContentPath)
	if headerPath != "" && headerPath != path {
		return returnError(ErrInvalidHeader, HeaderNameContentPath)
	}
	chunk.contentPath = path

	version, err := url.PathUnescape(fullpath[3])
	if err != nil {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	if _, err := strconv.ParseInt(version, 10, 64); err != nil {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	headerVersion := headers.Get(HeaderNameContentVersion)
	if headerVersion != "" && headerVersion != version {
		return returnError(ErrInvalidHeader, HeaderNameContentVersion)
	}
	chunk.contentVersion = version

	contentID, err := url.PathUnescape(fullpath[4])
	if err != nil || !isHexaString(contentID, 0) {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	headerContentID := headers.Get(HeaderNameContentID)
	if headerContentID != "" && !strings.EqualFold(headerContentID, contentID) {
		return returnError(ErrInvalidHeader, HeaderNameContentID)
	}
	chunk.contentID = strings.ToUpper(contentID)

	beginContentID := strings.LastIndex(headerFullpath, "/") + 1
	chunk.contentFullpath = headerFullpath[:beginContentID] + chunk.contentID
	return nil
}

// Check and load the content fullpath of the chunk.
func (chunk *chunkInfo) retrieveDestinationHeader(headers *http.Header,
	rawx *rawxService, srcChunkID string) error {
	destination := headers.Get("Destination")
	if destination == "" {
		return returnError(ErrMissingHeader, "Destination")
	}
	dstURL, err := url.ParseRequestURI(destination)
	if err != nil {
		return returnError(ErrInvalidHeader, "Destination")
	}
	if dstURL.Host != rawx.url {
		return os.ErrPermission
	}
	chunk.chunkID = filepath.Base(filepath.Clean(dstURL.Path))
	if !isHexaString(chunk.chunkID, 64) {
		return returnError(ErrInvalidHeader, "Destination")
	}
	chunk.chunkID = strings.ToUpper(chunk.chunkID)
	if chunk.chunkID == srcChunkID {
		return os.ErrPermission
	}
	return nil
}

// Check and load the info of the chunk.
func (chunk *chunkInfo) retrieveHeaders(headers *http.Header, chunkID string) error {
	chunk.contentStgPol = headers.Get(HeaderNameContentStgPol)
	if chunk.contentStgPol == "" {
		return returnError(ErrMissingHeader, HeaderNameContentStgPol)
	}
	chunk.contentChunkMethod = headers.Get(HeaderNameContentChunkMethod)
	if chunk.contentChunkMethod == "" {
		return returnError(ErrMissingHeader, HeaderNameContentChunkMethod)
	}

	chunkIDHeader := headers.Get(HeaderNameChunkID)
	if chunkIDHeader != "" && !strings.EqualFold(chunkIDHeader, chunkID) {
		return returnError(ErrInvalidHeader, HeaderNameChunkID)
	}
	chunk.chunkID = strings.ToUpper(chunkID)
	chunk.chunkPosition = headers.Get(HeaderNameChunkPosition)
	if chunk.chunkPosition == "" {
		return returnError(ErrMissingHeader, HeaderNameChunkPosition)
	}

	chunk.metachunkHash = headers.Get(HeaderNameMetachunkChecksum)
	if chunk.metachunkHash != "" {
		if !isHexaString(chunk.metachunkHash, 0) {
			return returnError(ErrInvalidHeader, HeaderNameMetachunkChecksum)
		}
		chunk.metachunkHash = strings.ToUpper(chunk.metachunkHash)
	}
	chunk.metachunkSize = headers.Get(HeaderNameMetachunkSize)
	if chunk.metachunkSize != "" {
		if _, err := strconv.ParseInt(chunk.metachunkSize, 10, 64); err != nil {
			return returnError(ErrInvalidHeader, HeaderNameMetachunkSize)
		}
	}

	chunk.chunkHash = headers.Get(HeaderNameChunkChecksum)
	if chunk.chunkHash != "" {
		if !isHexaString(chunk.chunkHash, 0) {
			return returnError(ErrInvalidHeader, HeaderNameChunkChecksum)
		}
		chunk.chunkHash = strings.ToUpper(chunk.chunkHash)
	}
	chunk.chunkSize = headers.Get(HeaderNameChunkSize)
	if chunk.chunkSize != "" {
		if _, err := strconv.ParseInt(chunk.chunkSize, 10, 64); err != nil {
			return returnError(ErrInvalidHeader, HeaderNameChunkSize)
		}
	}

	chunk.oioVersion = OioVersion
	return chunk.retrieveContentFullpathHeader(headers)
}

// Check and load the checksum and the size of the chunk and the metachunk
func (chunk *chunkInfo) retrieveTrailers(trailers *http.Header, ul *upload) error {
	trailerMetachunkHash := trailers.Get(HeaderNameMetachunkChecksum)
	if trailerMetachunkHash != "" {
		chunk.metachunkHash = trailerMetachunkHash
		if chunk.metachunkHash != "" {
			if !isHexaString(chunk.metachunkHash, 0) {
				return returnError(ErrInvalidHeader, HeaderNameMetachunkChecksum)
			}
			chunk.metachunkHash = strings.ToUpper(chunk.metachunkHash)
		}
	}
	trailerMetachunkSize := trailers.Get(HeaderNameMetachunkSize)
	if trailerMetachunkSize != "" {
		chunk.metachunkSize = trailerMetachunkSize
		if chunk.metachunkSize != "" {
			if _, err := strconv.ParseInt(chunk.metachunkSize, 10, 64); err != nil {
				return returnError(ErrInvalidHeader, HeaderNameMetachunkSize)
			}
		}
	}
	if strings.HasPrefix(chunk.contentChunkMethod, "ec/") {
		if chunk.metachunkHash == "" {
			return returnError(ErrMissingHeader, HeaderNameMetachunkChecksum)
		}
		if chunk.metachunkSize == "" {
			return returnError(ErrMissingHeader, HeaderNameMetachunkSize)
		}
	}

	trailerChunkHash := trailers.Get(HeaderNameChunkChecksum)
	if trailerChunkHash != "" {
		chunk.chunkHash = strings.ToUpper(trailerChunkHash)
	}
	ul.hash = strings.ToUpper(ul.hash)
	if chunk.chunkHash != "" {
		if !strings.EqualFold(chunk.chunkHash, ul.hash) {
			return returnError(ErrInvalidHeader, HeaderNameChunkChecksum)
		}
	} else {
		chunk.chunkHash = ul.hash
	}
	trailerChunkSize := trailers.Get(HeaderNameChunkSize)
	if trailerChunkSize != "" {
		chunk.chunkSize = trailerChunkSize
	}
	if chunk.chunkSize != "" {
		if _, err := strconv.ParseInt(chunk.chunkSize, 10, 64); err != nil {
			return returnError(ErrInvalidHeader, HeaderNameChunkSize)
		}
	}

	return nil
}

// Fill the headers of the reply with the attributes of the chunk
func (chunk *chunkInfo) fillHeaders(headers *http.Header) {
	setHeader := func(k, v string) {
		if len(v) > 0 {
			headers.Set(k, v)
		}
	}
	setHeader(HeaderNameFullpath, chunk.contentFullpath)
	setHeader(HeaderNameContainerID, chunk.containerID)
	setHeader(HeaderNameContentPath, chunk.contentPath)
	setHeader(HeaderNameContentVersion, chunk.contentVersion)
	setHeader(HeaderNameContentID, chunk.contentID)
	setHeader(HeaderNameContentStgPol, chunk.contentStgPol)
	setHeader(HeaderNameContentChunkMethod, chunk.contentChunkMethod)
	setHeader(HeaderNameMetachunkChecksum, chunk.metachunkHash)
	setHeader(HeaderNameChunkID, chunk.chunkID)
	setHeader(HeaderNameMetachunkSize, chunk.metachunkSize)
	setHeader(HeaderNameChunkPosition, chunk.chunkPosition)
	setHeader(HeaderNameChunkChecksum, chunk.chunkHash)
	setHeader(HeaderNameChunkSize, chunk.chunkSize)
	setHeader(HeaderNameXattrVersion, chunk.oioVersion)
}
