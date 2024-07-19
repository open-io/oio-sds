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
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"

	"openio-sds/rawx/defs"
	"openio-sds/rawx/logger"
)

type optionsMap map[string]string

// An array of all the string that evaluate as TRUE
var ok = []string{"ok", "yes", "true", "enable", "enabled", "yeah", "on", "1"}

// An array of all the string that evaluate as FALSE
var nok = []string{"ko", "no", "false", "disable", "disabled", "nope", "off", "wot?", "0"}

// regex to extract a double quoted string
var regexString = regexp.MustCompile(`^[^"]*("[^"\\]*(?:\\.[^"\\]*)*")[^"]*$`)

var loadedOpts = map[string]string{
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
	"shallow_copy":     "shallow_copy",

	"event_conn_attempts":  "event_conn_attempts",
	"max_connections":      "max_connections",
	"timeout_read_header":  "timeout_read_header",
	"timeout_read_request": "timeout_read_request",
	"timeout_write_reply":  "timeout_write_reply",
	"timeout_idle":         "timeout_idle",
	"timeout_conn_event":   "timeout_conn_event",
	"timeout_send_event":   "timeout_send_event",
	"headers_buffer_size":  "headers_buffer_size",

	"sock_tcp_cork":    "cork",
	"sock_tcp_nodelay": "nodelay",

	"events": "events",
	"topic":  "topic",

	"tls_cert_file": "tls_cert_file",
	"tls_key_file":  "tls_key_file",
	"tls_rawx_url":  "tls_rawx_url",

	"log_access_get":     "log_access_get",
	"log_access_put":     "log_access_put",
	"log_access_delete":  "log_access_delete",
	"log_access_format":  "log_access_format",
	"log_request_format": "log_request_format",
	"log_event_format":   "log_event_format",
	"log_format":         "log_format",
	"log_level":          "log_level",
	// TODO(jfs): also implement a cachedir

	"statsd_addr":   "statsd_addr",
	"statsd_prefix": "statsd_prefix",

	"graceful_stop_timeout": "graceful_stop_timeout",
}

// FIXME(jfs): Schedule the removal of these misleading options
var deprecatedOpts = map[string]string{
	"tcp_keepalive": "keepalive",

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
}

var prefixOpts = map[string]string{
	defs.ConfigPrefixKafka: defs.ConfigPrefixKafka,
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
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) > 1 {
			optionName := fields[0]
			optionValue := fields[1]
			if optionValue != "" && optionValue[0] == '"' {
				s, err := strconv.Unquote(regexString.ReplaceAllString(line, "$1"))
				if err != nil {
					logger.LogFatal("Unable to convert quoted string from line `%s`", line)
					continue
				}
				optionValue = s
			}
			for prefix, v := range prefixOpts {
				if strings.HasPrefix(optionName, prefix) {
					opts[strings.Replace(optionName, prefix, v, 1)] = optionValue
					break
				}
			}
			if v, found := loadedOpts[optionName]; found {
				opts[v] = optionValue
			}
			if v, found := deprecatedOpts[optionName]; found {
				logger.LogWarning("DEPRECATED option used: %s", fields[0])
				opts[v] = optionValue
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	return opts, nil
}

func (m optionsMap) getFloat(k string, def float64) float64 {
	v := m[k]
	if len(v) <= 0 {
		return def
	}
	f64, err := strconv.ParseFloat(v, 64)
	if err != nil {
		logger.LogFatal("Invalid float option for %s: %s (%s)", k, v, err.Error())
		return def
	}
	return f64
}

func (m optionsMap) getInt(k string, def int) int {
	v := m[k]
	if len(v) <= 0 {
		return def
	}
	i64, err := strconv.ParseInt(v, 0, 32)
	if err != nil {
		logger.LogFatal("Invalid integer option for %s: %s (%s)", k, v, err.Error())
		return def
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

// getString gets a string value from the map, or returns `def` if
// the key does not exist.
func (m optionsMap) getString(k string, def string) string {
	v, ok := m[k]
	if !ok {
		return def
	}
	return v
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
