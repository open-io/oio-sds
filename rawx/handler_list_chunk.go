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
	"net/http"
	"os"
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

func ListChunks(path string, marker string, min_to_return int) ([]string, bool, string, error) {
	var fileList []string
	nb_files := 0
	next_marker := ""
	// Read all the chunk files
	err := filepath.Walk(path, func(file string, f os.FileInfo, err error) error {
		if !f.IsDir() {
			// List chunks files after the marker
			if file > marker {
				chunk_name := filepath.Base(file)
				// Check if it is a valid chunk format
				if isHexaString(chunk_name, 24, 64) {
					fileList = append(fileList, chunk_name)
					nb_files++
				}
			}
		} else {
			if strings.HasSuffix(file, nonOptimalPlacementFolderName) ||
				strings.HasSuffix(file, orphansFolderName) ||
				strings.HasSuffix(file, markersFolderName) {
				// Skip rawx special directory
				return filepath.SkipDir
			}
			if file < marker && file != path {
				// Skip, the chunks has been listed in previous call
				return filepath.SkipDir
			}
			// This condition is defined here because we want the marker
			// to be the next folder after reaching the defined minimum number of chunks.
			// We want to take advantage of the listing already made to
			// return all the chunks in the directory listed.
			if nb_files >= min_to_return {
				// Define next folder as marker
				next_marker = file
				// We have already reached the maximum chunk files to return
				return errStopWalk
			}
		}
		return nil
	})
	if err != nil {
		if err == errStopWalk {
			// The list of chunks is truncated
			// we have reached the maximum of chunks we can return
			return fileList, true, next_marker, nil
		}
		return nil, false, next_marker, err
	}
	return fileList, false, next_marker, nil
}

func doGetListOfChunks(rr *rawxRequest) {
	// Get marker and limit parameters
	req_body, err := io.ReadAll(rr.req.Body)
	if err != nil {
		rr.replyCode(http.StatusBadRequest)
	}
	params := Params{MinToReturn: 1000 /*default value*/}
	json.Unmarshal(req_body, &params)
	chunks, is_truncated, marker, err := ListChunks(rr.rawx.path, params.Marker, params.MinToReturn)
	if err != nil {
		rr.replyCode(http.StatusInternalServerError)
	}
	response_data := ResponseData{}
	response_data.Marker = marker
	response_data.IsTruncated = is_truncated
	for _, chunk := range chunks {
		response_data.Chunks = append(response_data.Chunks, Chunk{ChunkId: chunk})
	}
	headers := rr.rep.Header()
	headers.Set("Content-Type", "application/json")
	json.NewEncoder(rr.rep).Encode(response_data)
	rr.replyCode(http.StatusOK)
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
