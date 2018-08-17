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
	"net"
	"net/http"
	"path/filepath"
	"regexp"
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

func checkMakeFileRepo(dir string) *FileRepository {
	basedir := filepath.Clean(dir)
	if !filepath.IsAbs(basedir) {
		log.Fatalf("Filerepo path must be absolute, got %s", basedir)
	}
	return MakeFileRepository(basedir)
}

func main() {
	_ = flag.String("D", "UNUSED", "Unused compatibility flag")
	verbosePtr := flag.Bool("v", false, "Verbose mode, this activates stderr traces")
	syslogIDPtr := flag.String("s", "", "Activates syslog traces with the given identifier")
	confPtr := flag.String("f", "", "Path to configuration file")
	flag.Parse()

	if flag.NArg() != 0 {
		log.Fatal("Unexpected positional argument detected")
	}

	if *verbosePtr {
		InitStderrLogger()
	} else if *syslogIDPtr != "" {
		InitSysLogger(*syslogIDPtr)
	} else {
		InitNoopLogger()
	}

	var opts optionsMap

	if len(*confPtr) <= 0 {
		log.Fatal("Missing configuration file")
	} else if cfg, err := filepath.Abs(*confPtr); err != nil {
		log.Fatal("Invalid configuration file path", err.Error())
	} else if opts, err = ReadConfig(cfg); err != nil {
		log.Fatal("Exiting with error: ", err.Error())
	}

	namespace := opts["ns"]
	rawxURL := opts["addr"]
	rawxID := opts["id"]
	checkNS(namespace)
	checkURL(rawxURL)

	// No service ID specified, using the service address instead
	if len(rawxID) <= 0 {
		rawxID = rawxURL
		LogInfo("No service ID, using ADDR %s", rawxURL)
	}

	filerepo := checkMakeFileRepo(opts["basedir"])
	filerepo.HashWidth = opts.getInt("hash_width", filerepo.HashWidth)
	filerepo.HashDepth = opts.getInt("hash_depth", filerepo.HashDepth)
	filerepo.SyncFile = opts.getBool("fsync_file", filerepo.SyncFile)
	filerepo.SyncDir = opts.getBool("fsync_dir", filerepo.SyncDir)
	filerepo.FallocateFile = opts.getBool("fallocate", filerepo.FallocateFile)

	chunkrepo := MakeChunkRepository(filerepo)
	if err := chunkrepo.Lock(namespace, rawxID); err != nil {
		log.Fatal("Volume lock error: ", err.Error())
	}

	rawx := rawxService{
		ns:       namespace,
		id:       rawxID,
		url:      rawxURL,
		repo:     chunkrepo,
		compress: opts.getBool("compress", false),
	}

	eventAgent := OioGetEventAgent(namespace)
	if eventAgent == "" {
		log.Fatal("Notifier error: no address")
	}
	notifier, err := MakeNotifier(eventAgent, &rawx)
	if err != nil {
		log.Fatal("Notifier error: ", err)
	}
	rawx.notifier = notifier
	rawx.notifier.start()

	if err = http.ListenAndServe(rawx.url, &rawx); err != nil {
		log.Fatal("HTTP error: ", err)
	}

	rawx.notifier.stop()
}
