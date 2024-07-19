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
	"io"
	"io/fs"
	"net/http"
	"openio-sds/rawx/iterator"
	"openio-sds/rawx/utils"
	"path/filepath"
)

const (
	HeaderIsTruncated = "X-oio-list-truncated"
	HeaderListMarker  = "X-oio-list-marker"
)

type Params struct {
	Marker string `json:"start_after"`
	// An indication of the expected number of chunks to be returned.
	// Not a hard maximum, because the number of returned elements will be HintMax plus the maximum number of files
	// in a leaf directory of a RAWX hierarchy.
	MinToReturn int `json:"min_to_return"`
}

type Chunk struct {
	ChunkId string `json:"chunk_id"`
}

type ResponseData struct {
	Chunks      []Chunk `json:"chunks"`
	IsTruncated bool    `json:"is_truncated"`
	Marker      string  `json:"marker"`
}

func ListChunks(path string, marker string, minToReturn int, maxWidth, maxDepth int) ([]string, bool, string, error) {
	var fileList []string
	onFile := func(file string, f fs.DirEntry, err error) error {
		basename := filepath.Base(file)
		// The iterator already produces the leaf directories, no subdir is expected to contain chunks.
		if utils.IsValidChunkId(basename) {
			// Let's just skip pending chunks
			fileList = append(fileList, basename)
		}
		return nil
	}

	var nextMarker string
	var err error
	it := iterator.NewPathIterator(marker, uint(maxWidth), uint(maxDepth)).Run()
	for {
		dir, ok := <-it
		if !ok { // Prefixes exhausted, there is no nextMarker to collect
			break
		}

		// Just iterate over one directory at a time, skipping dirs prior to the marker.
		e := filepath.WalkDir(filepath.Join(path, dir), onFile)
		if e != nil {
			err = e
			break
		}
		if len(fileList) >= minToReturn {
			if next, ok := <-it; ok {
				// Base the paginated iteration on the ideal list of directories instead of those
				// in place at the previous page request. It tends to avoid skipping directories created
				// between both requests.
				nextMarker = next
			}
			break
		}
	}
	return fileList, (nextMarker != ""), nextMarker, err
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
	chunks, isTruncated, marker, err := ListChunks(
		rr.rawx.path, marker, params.MinToReturn,
		rr.rawx.repo.sub.hashWidth, rr.rawx.repo.sub.hashDepth)
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
