// OpenIO SDS Go rawx
// Copyright (C) 2015-2019 OpenIO SAS
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Affero General Public
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
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
)

type optionsMap map[string]string

// readConfig -- fetch options from conf file
func readConfig(conf string) (optionsMap, error) {
	loadedOpts := map[string]string{
		"Listen":           "addr",
		"grid_namespace":   "ns",
		"grid_hash_width":  "hash_width",
		"grid_hash_depth":  "hash_depth",
		"grid_fsync":       "fsync_file",
		"grid_fsync_dir":   "fsync_dir",
		"grid_docroot":     "basedir",
		"grid_compression": "compression",
		"grid_fallocate":   "fallocate",
		"grid_service_id":  "id",
		// TODO(jfs): also implement a cachedir
	}
	var opts = make(map[string]string)
	f, err := os.OpenFile(conf, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 1 {
			if v, found := loadedOpts[fields[0]]; found {
				opts[v] = fields[1]
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	return opts, nil
}

func (m optionsMap) getInt(k string, def int) int {
	v := m[k]
	if len(v) <= 0 {
		return def
	}
	i64, err := strconv.ParseInt(v, 0, 32)
	if err != nil {
		log.Fatalf("Invalid integer option for %s: %s (%s)", k, v, err.Error())
		return 0
	}
	return int(i64)
}

func (m optionsMap) getBool(k string, def bool) bool {
	v := m[k]
	if len(v) <= 0 {
		return def
	}
	/* TODO(mbo): emit a warning for invalid value */
	return GetBool(v, def)
}

func GetBool(v string, def bool) bool {
	ok := []string{"ok", "yes", "true", "enable", "enabled", "yeah"}
	nok := []string{"ko", "no", "false", "disable", "disabled", "nope"}

	lv := strings.ToLower(v)
	for _, v0 := range ok {
		if v0 == lv {
			return true
		}
	}
	for _, v0 := range nok {
		if v0 == lv {
			return false
		}
	}
	return def
}
