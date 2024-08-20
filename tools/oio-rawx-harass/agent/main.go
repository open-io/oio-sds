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
		sz := 0
		key := "user.server.id"
		value := make([]byte, 2048)

		for _, path := range allPaths {
			sz, err = syscall.Getxattr(path, key, value)
			if err != nil {
				log.Fatalf("Fail to load attr=%s from vol=%s: err=%v", key, path, err)
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

	count := 0
	var listed, skipped uint32
	var buf bytes.Buffer
	buf.Reset()

	log.Debugf("Listing rawx [%s]", path)
	err := filepath.WalkDir(path, func(path string, info os.DirEntry, err error) error {
		if !info.IsDir() {
			if !strings.HasSuffix(path, ".pending") {
				buf.WriteString(filepath.Base(path))
				buf.WriteRune('\n')
				count++
				if (count % 1024) == 0 {
					w.Write(buf.Bytes())
					buf.Reset()
				}
			}
		}
		return nil
	})

	b := buf.Bytes()
	if len(b) > 0 {
		w.Write(b)
	}

	log.WithError(err).
		WithField("path", path).
		WithField("listed", listed).WithField("skipped", skipped).
		Debug("Done")
}
