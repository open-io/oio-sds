// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
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

// An array of all the string that evaluate as TRUE
var ok = []string{"ok", "yes", "true", "enable", "enabled", "yeah", "on"}

// An array of all the string that evaluate as FALSE
var nok = []string{"ko", "no", "false", "disable", "disabled", "nope", "off", "wot?"}

var loadedOpts = map[string]string{
	// Long historical names
	"grid_namespace":        "ns",
	"grid_hash_width":       "hash_width",
	"grid_hash_depth":       "hash_depth",
	"grid_fsync":            "fsync_file",
	"grid_fsync_dir":        "fsync_dir",
	"grid_docroot":          "basedir",
	"grid_compression":      "compression",
	"grid_compress":         "compression",
	"grid_fallocate":        "fallocate",
	"grid_service_id":       "id",
	"grid_checksum":         "checksum",
	"grid_buffer_size":      "buffer_size",
	"grid_fadvise_upload":   "fadvise_upload",
	"grid_fadvise_download": "fadvise_download",

	"listen":           "addr",
	"Listen":           "addr",
	"namespace":        "ns",
	"service_id":       "id",
	"syslog_id":        "syslog_id",
	"hash_width":       "hash_width",
	"hash_depth":       "hash_depth",
	"fsync":            "fsync_file",
	"fsync_dir":        "fsync_dir",
	"docroot":          "basedir",
	"compression":      "compression",
	"compress":         "compression",
	"fallocate":        "fallocate",
	"http_keepalive":   "keepalive",
	"checksum":         "checksum",
	"buffer_size":      "buffer_size",
	"fadvise_upload":   "fadvise_upload",
	"fadvise_download": "fadvise_download",
	"open_nonblock":    "nonblock",

	"timeout_read_header":  "timeout_read_header",
	"timeout_read_request": "timeout_read_request",
	"timeout_write_reply":  "timeout_write_reply",
	"timeout_idle":         "timeout_idle",
	"headers_buffer_size":  "headers_buffer_size",

	"sock_tcp_cork":    "cork",
	"sock_tcp_nodelay": "nodelay",

	"events": "events",

	"tls_cert_file": "tls_cert_file",
	"tls_key_file":  "tls_key_file",
	"tls_rawx_url":  "tls_rawx_url",

	"log_access_get":    "log_access_get",
	"log_access_put":    "log_access_put",
	"log_access_delete": "log_access_delete",
	// TODO(jfs): also implement a cachedir
}

// FIXME(jfs): Schedule the removal of these misleading options
var deprecatedOpts = map[string]string{
	"tcp_keepalive": "keepalive",
}

// readConfig -- fetch options from conf file and remap their name
// to a shorter form. This helps managing several aliases to the
// same variable.
func readConfig(conf string) (optionsMap, error) {
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
			if v, found := deprecatedOpts[fields[0]]; found {
				LogWarning("DEPRECATED option used: %s", fields[0])
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
