package main

import (
	"bufio"
	"log"
	"os"
	"strconv"
	"strings"
)

type optionsMap map[string]string

// ReadConfig -- fetch options from conf file
func ReadConfig(conf string) (optionsMap, error) {
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
	ok := []string{"ok", "yes", "true", "enable", "enabled", "yeah"}
	nok := []string{"ko", "no", "false", "disable", "disabled", "nope"}
	v := m[k]
	if len(v) <= 0 {
		return def
	}
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
	log.Fatalf("Invalid boolean value for %s: %s", k, v)
	return false
}
