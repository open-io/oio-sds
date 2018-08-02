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

/*
Parses and checks the CLI arguments, then ties together a repository and a
http handler.
*/

import (
	"flag"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
)

var (
	logger_access *log.Logger = nil
	logger_error  *log.Logger = nil
)

func checkURL(url string) {
	addr, err := net.ResolveTCPAddr("tcp", url)
	if err != nil || addr.Port <= 0 {
		log.Fatalf("%s is not a valid URL", url)
	}
}

// TODO(jfs): the pattern doesn't patch the requirement
func checkNS(ns string) {
	if ok, _ := regexp.MatchString("[0-9a-zA-Z]+(\\.[0-9a-zA-Z]+)*", ns); !ok {
		log.Fatalf("%s is not a valid namespace name", ns)
	}
}

func usage(why string) {
	log.Println("rawx NS IP:PORT BASEDIR")
	log.Fatal(why)
}

func checkUrl(url string) bool {
	addr, err := net.ResolveTCPAddr("tcp", url)
	if err != nil {
		return false
	}
	if addr.Port <= 0 {
		return false
	}
	return true
}

func checkNamespace(ns string) bool {
	ok, _ := regexp.MatchString("[0-9a-zA-Z]+(\\.[0-9a-zA-Z]+)*", ns)
	return ok
}

func checkMakeFileRepo(dir string) *FileRepository {
	basedir := filepath.Clean(dir)
	if !filepath.IsAbs(basedir) {
		log.Fatalf("Filerepo path must be absolute, got %s", basedir)
	}
	return MakeFileRepository(basedir)
}

func main() {
	_ = flag.String("D", "UNUSED", "Unused compatibility flag")
	confPtr := flag.String("f", "", "Path to configuration file")
	flag.Parse()

	if flag.NArg() != 0 {
		log.Fatal("Unexpected positional argument detected")
	}

	logger_access, _ = syslog.NewLogger(syslog.LOG_INFO|syslog.LOG_LOCAL0, 0)
	logger_error, _ = syslog.NewLogger(syslog.LOG_INFO|syslog.LOG_LOCAL1, 0)

	var opts optionsMap

	if len(*confPtr) <= 0 {
		log.Fatal("Missing configuration file")
	} else if cfg, err := filepath.Abs(*confPtr); err != nil {
		log.Fatal("Invalid configuration file path", err.Error())
	} else if opts, err = ReadConfig(cfg); err != nil {
		log.Fatal("Exiting with error: ", err.Error())
	}

	checkNS(opts["ns"])
	checkURL(opts["addr"])

	// No service ID specified, using the service address instead
	if len(opts["id"]) <= 0 {
		opts["id"] = opts["addr"]
		logger_error.Print("No service ID, using ADDR ", opts["addr"])
	}

	filerepo := checkMakeFileRepo(opts["basedir"])
	filerepo.HashWidth = opts.getInt("hash_width", filerepo.HashWidth)
	filerepo.HashDepth = opts.getInt("hash_depth", filerepo.HashDepth)
	filerepo.sync_file = opts.getBool("fsync_file", filerepo.sync_file)
	filerepo.sync_dir = opts.getBool("fsync_dir", filerepo.sync_dir)
	filerepo.fallocate_file = opts.getBool("fallocate", filerepo.fallocate_file)

	chunkrepo := MakeChunkRepository(filerepo)
	if err := chunkrepo.Lock(opts["ns"], opts["id"]); err != nil {
		logger_error.Fatal("Volume lock error: ", err.Error())
	}

	notifier, err := MakeBeanstalkNotifier("127.0.0.1:6009", "oio") // TODO(adu)
	if err != nil {
		logger_error.Fatal("Notifier error: ", err)
	}

	rawx := rawxService{
		ns:       opts["ns"],
		id:       opts["id"],
		url:      opts["addr"],
		repo:     chunkrepo,
		compress: opts.getBool("compress", false),
		notifier: notifier,
	}

	if err = http.ListenAndServe(rawx.url, &rawx); err != nil {
		logger_error.Fatal("HTTP error: ", err)
	}
}
