// OpenIO SDS oio-rawx-harass
// Copyright (C) 2019-2020 OpenIO SAS
// Copyright (C) 2021-2024 OVH SAS
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
	"bytes"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
	"openio-sds/tools/oio-rawx-harass/utils"
)

var allRawx = make(map[string]string)

func main() {
	// Load the mapping between rawx
	if allPaths, err := filepath.Glob("/srv/node/*/*/rawx-*"); err != nil {
		log.Fatal(err)
	} else {
		for _, path := range allPaths {
			value := make([]byte, 1024)
			if sz, err := syscall.Getxattr(path, "user.server.id", value); err != nil {
				log.Fatal(err)
			} else {
				id := string(value[:sz])
				allRawx[id] = path
			}
		}
	}

	http.HandleFunc("/", handleList)

	listenUrl := fmt.Sprintf("0.0.0.0:%d", utils.DiscoveryPort)
	if err := http.ListenAndServe(listenUrl, nil); err != nil {
		log.Fatal(err)
	}
}

func handleList(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[1:]
	path, found := allRawx[id]
	if !found {
		w.WriteHeader(http.StatusNotFound)
	}

	var listed, skipped uint32
	var buf bytes.Buffer

	log.Debugf("Listing rawx [%s]", path)
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			if !strings.HasSuffix(path, ".pending") {
				buf.Reset()
				buf.WriteString(filepath.Base(path))
				buf.WriteRune(' ')
				buf.WriteString(strconv.FormatUint(uint64(info.Size()), 10))
				buf.WriteRune('\n')
				w.Write(buf.Bytes())
			}
		}
		return nil
	})
	log.WithError(err).
		WithField("path", path).
		WithField("listed", listed).WithField("skipped", skipped).
		Debug("Done")
}
