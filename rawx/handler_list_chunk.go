// OpenIO SDS Go rawx
// Copyright (C) 2024 OVH SAS
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
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
)

var (
	errStopWalk = errors.New("skip everything and stop the walk")
)

const (
	HeaderIsTruncated = "X-oio-list-truncated"
	HeaderListMarker  = "X-oio-list-marker"
)

type Params struct {
	Marker      string `json:"start_after"`
	MinToReturn int    `json:"min_to_return"`
}

type Chunk struct {
	ChunkId string `json:"chunk_id"`
}

type ResponseData struct {
	Chunks      []Chunk `json:"chunks"`
	IsTruncated bool    `json:"is_truncated"`
	Marker      string  `json:"marker"`
}

func ListChunks(path string, marker string, minToReturn int, maxWidth int) ([]string, bool, string, error) {
	var fileList []string
	nbFiles := 0
	nextMarker := ""
	// Read all the chunk files
	err := filepath.WalkDir(path, func(file string, f fs.DirEntry, err error) error {
		if !f.IsDir() {
			// List chunks files after the marker
			if file > marker {
				chunk := filepath.Base(file)
				// Check if it is a valid chunk format
				if isHexaString(chunk, 24, 64) {
					fileList = append(fileList, chunk)
					nbFiles++
				}
			}
		} else {
			// it is not the rawx service volume directory
			if file != path {
				if !isHexaString(filepath.Base(file), maxWidth, maxWidth) {
					// Skip rawx special directory
					return filepath.SkipDir
				}
				// it is a directory before the marker
				// it is not a direct parent directory in case the marker is a chunk file
				if file < marker && !strings.Contains(marker, file) {
					// Skip, the chunks has been listed in previous call
					return filepath.SkipDir
				}
				// This condition is defined here because we want the marker
				// to be the next folder after reaching the defined minimum number of chunks.
				// We want to take advantage of the listing already made to
				// return all the chunks in the directory listed.
				if nbFiles >= minToReturn {
					// Define next folder as marker
					nextMarker = file
					// We have already reached the maximum chunk files to return
					return errStopWalk
				}
			}
		}
		return nil
	})
	if err != nil {
		if err == errStopWalk {
			// The list of chunks is truncated
			// we have reached the maximum of chunks we can return
			return fileList, true, nextMarker, nil
		}
		return nil, false, nextMarker, err
	}
	return fileList, false, nextMarker, nil
}

func doGetListOfChunks(rr *rawxRequest) {
	// Get marker and limit parameters
	requestBody, err := io.ReadAll(rr.req.Body)
	if err != nil {
		rr.replyCode(http.StatusBadRequest)
		return
	}
	params := Params{MinToReturn: 1000 /*default value*/}
	json.Unmarshal(requestBody, &params)
	marker := params.Marker
	// Check if the marker is a chunkId
	if isHexaString(marker, 24, 64) {
		marker = rr.rawx.repo.sub.nameToRelPath(marker)
	}
	chunks, isTruncated, marker, err := ListChunks(
		rr.rawx.path, marker, params.MinToReturn, rr.rawx.repo.sub.hashWidth)
	if err != nil {
		rr.replyCode(http.StatusInternalServerError)
		return
	}
	responseData := ResponseData{}
	responseData.Marker = marker
	responseData.IsTruncated = isTruncated
	for _, chunk := range chunks {
		responseData.Chunks = append(responseData.Chunks, Chunk{ChunkId: chunk})
	}
	headers := rr.rep.Header()
	headers.Set("Content-Type", "application/json")
	json.NewEncoder(rr.rep).Encode(responseData)
}

func (rr *rawxRequest) serveListOfChunks() {
	if !rr.rawx.isIOok() {
		rr.replyIoError(rr.rawx)
	} else {
		switch rr.req.Method {
		case "GET":
			doGetListOfChunks(rr)
		default:
			rr.replyCode(http.StatusMethodNotAllowed)
		}
	}
}
