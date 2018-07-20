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

func main() {
	flag.Parse()
	if flag.NArg() != 3 {
		usage("Missing positional arguments")
	}

	ns := flag.Arg(0)
	if !checkNamespace(ns) {
		usage("Invalid namespace Format")
	}

	ipPort := flag.Arg(1)
	if !checkUrl(ipPort) {
		usage("Invalid URL format")
	}

	basedir := filepath.Clean(flag.Arg(2))
	if !filepath.IsAbs(basedir) {
		usage("Basedir must be absolute")
	}

	var rawxid string

	filerepo := MakeFileRepository(basedir, nil)
	chunkrepo := MakeChunkRepository(filerepo)
	if err := chunkrepo.Lock(ns, ipPort); err != nil {
		usage("Basedir cannot be locked with xattr : " + err.Error())
	}

	logger_access, _ := syslog.NewLogger(syslog.LOG_INFO|syslog.LOG_LOCAL0, 0)
	logger_error, _ := syslog.NewLogger(syslog.LOG_INFO|syslog.LOG_LOCAL1, 0)
	rawx := rawxService{
		ns:            ns,
		id:            rawxid,
		url:           ipPort,
		repo:          chunkrepo,
		compress:      false,
		logger_access: logger_access,
		logger_error:  logger_error,
	}

	http.Handle("/chunk", &chunkHandler{&rawx})
	http.Handle("/info", &statHandler{&rawx})
	http.Handle("/stat", &statHandler{&rawx})

	// Some usages of the RAWX API don't use any prefix when calling
	// operations on chunks.
	http.Handle("/", &chunkHandler{&rawx})

	if err := http.ListenAndServe(rawx.url, nil); err != nil {
		log.Fatal("HTTP error : ", err)
	}
}
