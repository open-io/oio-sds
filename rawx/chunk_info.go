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
	"encoding/json"
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
	ChunkSize          string `json:"chunk_size,omitempty"`
	OioVersion         string `json:"oio_version,omitempty"`
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
	loggerError.Printf("%s: %s", err, message)
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
	if chunk.ChunkID == "" || chunk.ContentFullpath == "" {
		return errors.New("Missing chunk ID or fullpath")
	}

	return out.SetAttr(AttrNameFullPrefix+chunk.ChunkID, []byte(chunk.ContentFullpath))
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
		{AttrNameMetachunkChecksum, &chunk.MetachunkHash},
		{AttrNameMetachunkSize, &chunk.MetachunkSize},
		{AttrNameChunkChecksum, &chunk.ChunkHash},
		{AttrNameChunkSize, &chunk.ChunkSize},
		{AttrNameChunkPosition, &chunk.ChunkPosition},
		{AttrNameContentChunkMethod, &chunk.ContentChunkMethod},
		{AttrNameContentStgPol, &chunk.ContentStgPol},
		{AttrNameOioVersion, &chunk.OioVersion},
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
	chunk.ChunkID = chunkID
	fullpath := strings.Split(contentFullpath, "/")
	if len(fullpath) == 5 {
		chunk.ContentFullpath = contentFullpath
		account, _ := url.PathUnescape(fullpath[0])
		container, _ := url.PathUnescape(fullpath[1])
		chunk.ContainerID = cidFromName(account, container)
		chunk.ContentPath, _ = url.PathUnescape(fullpath[2])
		chunk.ContentVersion, _ = url.PathUnescape(fullpath[3])
		chunk.ContentID, _ = url.PathUnescape(fullpath[4])
	}

	var detailedAttrs = []detailedAttr{
		{AttrNameContentChunkMethod, &chunk.ContentChunkMethod},
		{AttrNameContentStgPol, &chunk.ContentStgPol},
		{AttrNameMetachunkChecksum, &chunk.MetachunkHash},
		{AttrNameMetachunkSize, &chunk.MetachunkSize},
		{AttrNameChunkPosition, &chunk.ChunkPosition},
		{AttrNameChunkChecksum, &chunk.ChunkHash},
		{AttrNameChunkSize, &chunk.ChunkSize},
		{AttrNameOioVersion, &chunk.OioVersion},
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
	chunk.ContainerID = containerID

	path, err := url.PathUnescape(fullpath[2])
	if err != nil || path == "" {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	headerPath := headers.Get(HeaderNameContentPath)
	if headerPath != "" && headerPath != path {
		return returnError(ErrInvalidHeader, HeaderNameContentPath)
	}
	chunk.ContentPath = path

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
	chunk.ContentVersion = version

	contentID, err := url.PathUnescape(fullpath[4])
	if err != nil || !isHexaString(contentID, 0) {
		return returnError(ErrInvalidHeader, HeaderNameFullpath)
	}
	headerContentID := headers.Get(HeaderNameContentID)
	if headerContentID != "" && !strings.EqualFold(headerContentID, contentID) {
		return returnError(ErrInvalidHeader, HeaderNameContentID)
	}
	chunk.ContentID = strings.ToUpper(contentID)

	beginContentID := strings.LastIndex(headerFullpath, "/") + 1
	chunk.ContentFullpath = headerFullpath[:beginContentID] + chunk.ContentID
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
	chunk.ChunkID = filepath.Base(filepath.Clean(dstURL.Path))
	if !isHexaString(chunk.ChunkID, 64) {
		return returnError(ErrInvalidHeader, "Destination")
	}
	chunk.ChunkID = strings.ToUpper(chunk.ChunkID)
	if chunk.ChunkID == srcChunkID {
		return os.ErrPermission
	}
	return nil
}

// Check and load the info of the chunk.
func (chunk *chunkInfo) retrieveHeaders(headers *http.Header, chunkID string) error {
	chunk.ContentStgPol = headers.Get(HeaderNameContentStgPol)
	if chunk.ContentStgPol == "" {
		return returnError(ErrMissingHeader, HeaderNameContentStgPol)
	}
	chunk.ContentChunkMethod = headers.Get(HeaderNameContentChunkMethod)
	if chunk.ContentChunkMethod == "" {
		return returnError(ErrMissingHeader, HeaderNameContentChunkMethod)
	}

	chunkIDHeader := headers.Get(HeaderNameChunkID)
	if chunkIDHeader != "" && !strings.EqualFold(chunkIDHeader, chunkID) {
		return returnError(ErrInvalidHeader, HeaderNameChunkID)
	}
	chunk.ChunkID = strings.ToUpper(chunkID)
	chunk.ChunkPosition = headers.Get(HeaderNameChunkPosition)
	if chunk.ChunkPosition == "" {
		return returnError(ErrMissingHeader, HeaderNameChunkPosition)
	}

	chunk.MetachunkHash = headers.Get(HeaderNameMetachunkChecksum)
	if chunk.MetachunkHash != "" {
		if !isHexaString(chunk.MetachunkHash, 0) {
			return returnError(ErrInvalidHeader, HeaderNameMetachunkChecksum)
		}
		chunk.MetachunkHash = strings.ToUpper(chunk.MetachunkHash)
	}
	chunk.MetachunkSize = headers.Get(HeaderNameMetachunkSize)
	if chunk.MetachunkSize != "" {
		if _, err := strconv.ParseInt(chunk.MetachunkSize, 10, 64); err != nil {
			return returnError(ErrInvalidHeader, HeaderNameMetachunkSize)
		}
	}

	chunk.ChunkHash = headers.Get(HeaderNameChunkChecksum)
	if chunk.ChunkHash != "" {
		if !isHexaString(chunk.ChunkHash, 0) {
			return returnError(ErrInvalidHeader, HeaderNameChunkChecksum)
		}
		chunk.ChunkHash = strings.ToUpper(chunk.ChunkHash)
	}
	chunk.ChunkSize = headers.Get(HeaderNameChunkSize)
	if chunk.ChunkSize != "" {
		if _, err := strconv.ParseInt(chunk.ChunkSize, 10, 64); err != nil {
			return returnError(ErrInvalidHeader, HeaderNameChunkSize)
		}
	}

	chunk.OioVersion = OioVersion
	return chunk.retrieveContentFullpathHeader(headers)
}

// Check and load the checksum and the size of the chunk and the metachunk
func (chunk *chunkInfo) retrieveTrailers(trailers *http.Header, ul *upload) error {
	trailerMetachunkHash := trailers.Get(HeaderNameMetachunkChecksum)
	if trailerMetachunkHash != "" {
		chunk.MetachunkHash = trailerMetachunkHash
		if chunk.MetachunkHash != "" {
			if !isHexaString(chunk.MetachunkHash, 0) {
				return returnError(ErrInvalidHeader, HeaderNameMetachunkChecksum)
			}
			chunk.MetachunkHash = strings.ToUpper(chunk.MetachunkHash)
		}
	}
	trailerMetachunkSize := trailers.Get(HeaderNameMetachunkSize)
	if trailerMetachunkSize != "" {
		chunk.MetachunkSize = trailerMetachunkSize
		if chunk.MetachunkSize != "" {
			if _, err := strconv.ParseInt(chunk.MetachunkSize, 10, 64); err != nil {
				return returnError(ErrInvalidHeader, HeaderNameMetachunkSize)
			}
		}
	}
	if strings.HasPrefix(chunk.ContentChunkMethod, "ec/") {
		if chunk.MetachunkHash == "" {
			return returnError(ErrMissingHeader, HeaderNameMetachunkChecksum)
		}
		if chunk.MetachunkSize == "" {
			return returnError(ErrMissingHeader, HeaderNameMetachunkSize)
		}
	}

	trailerChunkHash := trailers.Get(HeaderNameChunkChecksum)
	if trailerChunkHash != "" {
		chunk.ChunkHash = strings.ToUpper(trailerChunkHash)
	}
	ul.hash = strings.ToUpper(ul.hash)
	if chunk.ChunkHash != "" {
		if !strings.EqualFold(chunk.ChunkHash, ul.hash) {
			return returnError(ErrInvalidHeader, HeaderNameChunkChecksum)
		}
	} else {
		chunk.ChunkHash = ul.hash
	}
	trailerChunkSize := trailers.Get(HeaderNameChunkSize)
	if trailerChunkSize != "" {
		chunk.ChunkSize = trailerChunkSize
	}
	if chunk.ChunkSize != "" {
		if _, err := strconv.ParseInt(chunk.ChunkSize, 10, 64); err != nil {
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
	setHeader(HeaderNameFullpath, chunk.ContentFullpath)
	setHeader(HeaderNameContainerID, chunk.ContainerID)
	setHeader(HeaderNameContentPath, chunk.ContentPath)
	setHeader(HeaderNameContentVersion, chunk.ContentVersion)
	setHeader(HeaderNameContentID, chunk.ContentID)
	setHeader(HeaderNameContentStgPol, chunk.ContentStgPol)
	setHeader(HeaderNameContentChunkMethod, chunk.ContentChunkMethod)
	setHeader(HeaderNameMetachunkChecksum, chunk.MetachunkHash)
	setHeader(HeaderNameChunkID, chunk.ChunkID)
	setHeader(HeaderNameMetachunkSize, chunk.MetachunkSize)
	setHeader(HeaderNameChunkPosition, chunk.ChunkPosition)
	setHeader(HeaderNameChunkChecksum, chunk.ChunkHash)
	setHeader(HeaderNameChunkSize, chunk.ChunkSize)
	setHeader(HeaderNameXattrVersion, chunk.OioVersion)
}

func (chunk *chunkInfo) getJSON(rawx *rawxService) string {
	chunkJSON, _ := json.Marshal(struct {
		chunkInfo
		VolumeAddr string `json:"volume_id,omitempty"`
		VolumeID   string `json:"volume_service_id,omitempty"`
	}{
		chunkInfo:  chunkInfo(*chunk),
		VolumeAddr: rawx.url,
		VolumeID:   rawx.id,
	})
	return string(chunkJSON)
}
