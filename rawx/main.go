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
// Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public
// License along with this program. If not, see <http://www.gnu.org/licenses/>.

package main

/*
Parses and checks the CLI arguments, then ties together a repository and a
http handler.
*/

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var xattrBufferPool = newBufferPool(xattrBufferTotalSizeDefault, xattrBufferSizeDefault)

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

func installSigHandlers(srv *http.Server) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
		syscall.SIGINT,
		syscall.SIGTERM)

	go func() {
		for {
			switch <-signalChan {
			case syscall.SIGUSR1:
				increaseVerbosity()
				go func() {
					time.Sleep(time.Minute * 15)
					resetVerbosity()
				}()
			case syscall.SIGUSR2:
				resetVerbosity()
			case syscall.SIGINT, syscall.SIGTERM:
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if err := srv.Shutdown(ctx); err != nil {
					LogWarning("graceful shutdown error: %v", err)
				}
				cancel() // releases resources if Shutdown completes before timeout elapses
			}
		}
	}()
}

func taskProbeRepository(rawx *rawxService, finished chan bool) {
	for {
		for i := 0; i < 5; i++ {
			time.Sleep(time.Second)
			select {
			case <-finished:
				LogInfo("Stop the probe to check the repository")
				return
			default:
			}
		}

		/* Try a directory creation */
		path := fmt.Sprintf("%s/probe-%s", rawx.path,
			randomString(16, hexaCharacters))
		LogDebug("Probing directory %s", path)
		err := os.Mkdir(path, 0755)
		os.Remove(path)
		if err != nil {
			msg := fmt.Sprintf("IO error on %s %s: %v", rawx.getURL(), path,
				err)
			LogWarning(msg)
			rawx.lastIOError = time.Now()
			rawx.lastIOMsg = msg
			continue
		}

		/* Try a file creation */
		path = fmt.Sprintf("%s/probe-%s", rawx.path,
			randomString(16, hexaCharacters))
		LogDebug("Probing file %s", path)
		file, err := os.Create(path)
		file.Close()
		os.Remove(path)
		if err != nil {
			msg := fmt.Sprintf("IO error on %s %s: %v", rawx.getURL(), path,
				err)
			LogWarning(msg)
			rawx.lastIOError = time.Now()
			rawx.lastIOMsg = msg
			continue
		}

		rawx.lastIOSuccess = time.Now()
		rawx.lastIOMsg = "n/a"
	}
}

func main() {
	var err error

	_ = flag.String("D", "UNUSED", "Unused compatibility flag")
	verbosePtr := flag.Bool("v", false, "Verbose mode, this activates stderr traces")
	syslogIDPtr := flag.String("s", "", "Activates syslog traces with the given identifier")
	confPtr := flag.String("f", "", "Path to configuration file")
	servicingPtr := flag.Bool("servicing", false, "Don't lock volume")
	flag.Parse()

	if flag.NArg() != 0 {
		log.Fatal("Unexpected positional argument detected")
	}

	if *verbosePtr {
		maximizeVerbosity()
	}

	var opts optionsMap

	if len(*confPtr) <= 0 {
		log.Fatal("Missing configuration file")
	} else if cfg, err := filepath.Abs(*confPtr); err != nil {
		log.Fatalf("Invalid configuration file path: %v", err.Error())
	} else if opts, err = readConfig(cfg); err != nil {
		log.Fatalf("Exiting with error: %v", err.Error())
	}

	if opts["log_format"] != "" {
		logFormat = opts["log_format"]
	}
	if opts["log_access_format"] != "" {
		logAccessFormat = opts["log_access_format"]
	}
	if err := InitLogTemplates(); err != nil {
		log.Fatalf("Unable to init log templates: %v", err.Error())
	}

	if logExtremeVerbosity {
		InitStderrLogger()
	} else if *syslogIDPtr != "" {
		InitSysLogger(*syslogIDPtr)
	} else if v, ok := opts["syslog_id"]; ok {
		InitSysLogger(v)
	} else {
		InitNoopLogger()
	}

	chunkrepo := chunkRepository{}
	namespace := opts["ns"]
	rawxURL := opts["addr"]
	rawxID := opts["id"]
	notifAllowed = opts.getBool("events", configDefaultEvents)

	accessLogPut = opts.getBool("log_access_put", configAccessLogDefaultPut)
	accessLogGet = opts.getBool("log_access_get", configAccessLogDefaultGet)
	accessLogDel = opts.getBool("log_access_del", configAccessLogDefaultDelete)

	checkNS(namespace)
	checkURL(rawxURL)

	// Init the actual chunk storage
	if err := chunkrepo.sub.init(opts["basedir"]); err != nil {
		LogFatal("Invalid directories: %v", err)
	}
	chunkrepo.sub.hashWidth = opts.getInt("hash_width", chunkrepo.sub.hashWidth)
	chunkrepo.sub.hashDepth = opts.getInt("hash_depth", chunkrepo.sub.hashDepth)
	chunkrepo.sub.syncFile = opts.getBool("fsync_file", chunkrepo.sub.syncFile)
	chunkrepo.sub.syncDir = opts.getBool("fsync_dir", chunkrepo.sub.syncDir)
	chunkrepo.sub.fallocateFile = opts.getBool("fallocate", chunkrepo.sub.fallocateFile)
	chunkrepo.sub.openNonBlock = opts.getBool("nonblock", configDefaultOpenNonblock)

	rawx := rawxService{
		ns:            namespace,
		url:           rawxURL,
		tlsUrl:        opts["tls_rawx_url"],
		path:          chunkrepo.sub.root,
		id:            rawxID,
		repo:          chunkrepo,
		bufferSize:    1024 * opts.getInt("buffer_size", uploadBufferSizeDefault/1024),
		checksumMode:  checksumAlways,
		compression:   opts["compression"],
		lastIOError:   time.Time{},
		lastIOSuccess: time.Time{},
		lastIOMsg:     "n/a",
		lastIOReport:  time.Time{},
	}

	// Clamp the buffer size to admitted values
	if rawx.bufferSize > uploadBufferSizeMax {
		rawx.bufferSize = uploadBufferSizeMax
	}
	if rawx.bufferSize < uploadBufferSizeMin {
		rawx.bufferSize = uploadBufferSizeMin
	}
	// In case of a misconfiguration
	if rawx.bufferSize < uploadBatchSize {
		rawx.bufferSize = uploadBatchSize
	}

	rawx.uploadBufferPool = newBufferPool(uploadBufferTotalSizeDefault, rawx.bufferSize)

	// Patch the checksum mode
	if v, ok := opts["checksum"]; ok {
		if v == "smart" {
			rawx.checksumMode = checksumSmart
		} else if GetBool(v, true) {
			rawx.checksumMode = checksumAlways
		} else {
			rawx.checksumMode = checksumNever
		}
	}

	// Patch the fadvise() upon upload
	if v, ok := opts["fadvise_upload"]; ok {
		if strings.ToLower(v) == "cache" {
			chunkrepo.sub.fadviseUpload = configFadviseCache
		} else if strings.ToLower(v) == "nocache" {
			chunkrepo.sub.fadviseUpload = configFadviseNocache
		} else if GetBool(v, false) {
			chunkrepo.sub.fadviseUpload = configFadviseYes
		}
	}

	// Patch the fadvise() upon download
	if v, ok := opts["fadvise_download"]; ok {
		if strings.ToLower(v) == "cache" {
			chunkrepo.sub.fadviseDownload = configFadviseCache
		} else if strings.ToLower(v) == "nocache" {
			chunkrepo.sub.fadviseDownload = configFadviseNocache
		} else if GetBool(v, false) {
			chunkrepo.sub.fadviseDownload = configFadviseYes
		}
	}

	eventAgent := OioGetEventAgent(namespace)
	if eventAgent == "" {
		LogFatal("Notifier error: no address")
	}

	rawx.notifier, err = MakeNotifier(eventAgent, &rawx)
	if err != nil {
		LogFatal("Notifier error: %v", err)
	}

	toReadHeader := opts.getInt("timeout_read_header", timeoutReadHeader)
	toReadRequest := opts.getInt("timeout_read_request", timeoutReadRequest)
	toWrite := opts.getInt("timeout_write_reply", timeoutWrite)
	toIdle := opts.getInt("timeout_idle", timeoutIdle)

	/* need to be duplicated for HTTP and HTTPS */
	srv := http.Server{
		Addr:              rawx.url,
		Handler:           &rawx,
		TLSConfig:         nil,
		ReadHeaderTimeout: time.Duration(toReadHeader) * time.Second,
		ReadTimeout:       time.Duration(toReadRequest) * time.Second,
		WriteTimeout:      time.Duration(toWrite) * time.Second,
		IdleTimeout:       time.Duration(toIdle) * time.Second,
		// The default is at 1MiB but the RAWX never needs that
		MaxHeaderBytes: opts.getInt("headers_buffer_size", 65536),
	}

	tlsSrv := http.Server{
		Addr:              rawx.tlsUrl,
		Handler:           &rawx,
		TLSConfig:         nil,
		ReadHeaderTimeout: time.Duration(toReadHeader) * time.Second,
		ReadTimeout:       time.Duration(toReadRequest) * time.Second,
		WriteTimeout:      time.Duration(toWrite) * time.Second,
		IdleTimeout:       time.Duration(toIdle) * time.Second,
		// The default is at 1MiB but the RAWX never needs that
		MaxHeaderBytes: opts.getInt("headers_buffer_size", 65536),
	}

	flagNoDelay := opts.getBool("nodelay", configDefaultNoDelay)
	flagCork := opts.getBool("cork", configDefaultCork)
	if flagNoDelay || flagCork {
		srv.ConnState = func(cnx net.Conn, st http.ConnState) {
			setOpt := func(dom, flag, val int) {
				if tcpCnx, ok := cnx.(*net.TCPConn); ok {
					if rawCnx, err := tcpCnx.SyscallConn(); err == nil {
						rawCnx.Control(func(fd uintptr) {
							syscall.SetsockoptInt(int(fd), dom, flag, val)
						})
					}
				}
			}
			switch st {
			case http.StateNew:
				if flagNoDelay {
					setOpt(syscall.SOL_TCP, syscall.TCP_NODELAY, 1)
				}
			case http.StateActive:
				if flagCork {
					setOpt(syscall.SOL_TCP, syscall.TCP_CORK, 1)
				}
			case http.StateIdle:
				if flagCork {
					setOpt(syscall.SOL_TCP, syscall.TCP_CORK, 0)
				}
			}
		}
	}

	keepalive := opts.getBool("keepalive", configDefaultHttpKeepalive)
	srv.SetKeepAlivesEnabled(keepalive)
	tlsSrv.SetKeepAlivesEnabled(keepalive)

	installSigHandlers(&srv)
	installSigHandlers(&tlsSrv)

	if !*servicingPtr {
		id := rawx.id
		if id == "" {
			id = rawx.url
		}
		if err := chunkrepo.lock(namespace, id); err != nil {
			LogFatal("Volume lock error: %v", err.Error())
		}
	}

	if logExtremeVerbosity {
		srv.ConnState = func(cnx net.Conn, state http.ConnState) {
			LogDebug("%v %v %v", cnx.LocalAddr(), cnx.RemoteAddr(), state)
		}
		tlsSrv.ConnState = func(cnx net.Conn, state http.ConnState) {
			LogDebug("%v %v %v", cnx.LocalAddr(), cnx.RemoteAddr(), state)
		}
	}

	finished := make(chan bool)
	go taskProbeRepository(&rawx, finished)

	if err := Run(&srv, &tlsSrv, opts); err != nil {
		LogWarning("HTTP Server exiting: %v", err)
	}

	finished <- true
	rawx.notifier.stop()
	logger.close()
}
