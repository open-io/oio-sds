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
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"openio-sds/rawx/defs"
	"openio-sds/rawx/utils"
)

type httpServer struct {
	server http.Server
	socket *net.TCPListener
}

var xattrBufferPool = utils.NewBufferPool(defs.XattrBufferTotalSizeDefault, defs.XattrBufferSizeDefault)

// variable to track if a child process has been forked
var childPid int = 0

// notify systemd using sd_notify
// more to read: https://www.freedesktop.org/software/systemd/man/sd_notify.html#Description
func updateSystemd(status string) (notify_socket string) {
	notify_socket = os.Getenv("NOTIFY_SOCKET")

	if notify_socket == "" || status == "" {
		LogDebug("unable to send status to systemd as NOTIFY_SOCKET env variable is not set")
		return
	}

	addr := &net.UnixAddr{
		Name: notify_socket,
		Net:  "unixgram",
	}

	LogDebug("notifying systemd with: %s", status)

	conn, err := net.DialUnix(addr.Net, nil, addr)
	// Error connecting to NOTIFY_SOCKET
	if err != nil {
		LogWarning("Unable to dial NOTIFY_SOCKET(%s): %v", notify_socket, err)
		return
	}
	defer conn.Close()
	if _, err = conn.Write([]byte(status)); err != nil {
		LogWarning("Unable to send state %s to systemd: %v", status, err)
		return
	}

	return
}

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

func installSigHandlers(srv *httpServer, srvTls *httpServer, timeout time.Duration, wg *sync.WaitGroup) {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan,
		syscall.SIGUSR1,
		syscall.SIGUSR2,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM)
	servers := []*httpServer{}
	if srv != nil {
		servers = append(servers, srv)
	}
	if srvTls != nil {
		servers = append(servers, srvTls)
	}

	go func() {
		ongoing_stop := false

		for {
			sig := <-signalChan
			LogInfo("Received signal %s", sig)

			switch sig {

			// SIGUSR1 increase verbosity for 15 minutes
			case syscall.SIGUSR1:
				// run in a goroutine to prevent the time.Sleep to lock
				// the current (sig handler) goroutine
				go func() {
					increaseVerbosity()
					time.Sleep(time.Minute * 15)
					resetVerbosity()
				}()

			// SIGUSR1 reset verbosity
			case syscall.SIGUSR2:
				resetVerbosity()

			// INT exits immediately (timeout = 0)
			// TERM exits after all requests are finished or at timeout expiration
			//      if timeout is negative, wait for ever
			//      if timeout is 0, exit immediately
			case syscall.SIGTERM, syscall.SIGINT:

				if childPid == 0 {
					updateSystemd(fmt.Sprintf("STOPPING=1\nSTATUS=received %s signal, quitting", sig))
				}

				if sig == syscall.SIGINT {
					timeout = 0
				} else {
					if ongoing_stop {
						LogWarning("A graceful stop is already on going, forcing to exit immediately")
						timeout = 0
					}
				}

				ongoing_stop = true

				for i := 0; i < len(servers); i++ {
					server := servers[i]

					// run in a go routine as the Shutdown function is blocking the current goroutine
					go func() {
						var ctx context.Context
						if timeout < 0 {
							LogInfo("Shutting down %s server once all requests are over", server.server.Addr)
							ctx = context.Background()
						} else {
							if timeout > 0 {
								LogInfo("Shutting down %s server after all request are over or after %s", server.server.Addr, timeout)
							} else {
								LogInfo("Shutting down %s server immediately", server.server.Addr)
							}
							var cancel context.CancelFunc
							ctx, cancel = context.WithTimeout(context.Background(), timeout)
							defer cancel()
						}

						// increment the waitgroup to prevent the main loop to exit too early
						wg.Add(1)
						defer wg.Done()

						// stops the server waiting for all requests to finish (or for timeout to expires if set)
						if err := server.server.Shutdown(ctx); err != nil {
							LogWarning("HTTP shutdown (%s) error: %v", server.server.Addr, err.Error())
						}
					}()
				}

			// HUP is used to trigger a graceful restart
			// only 1 at a time can be done
			case syscall.SIGHUP:
				if ongoing_stop {
					LogWarning("A graceful stop is already on going, ignoring %s", sig)
					continue
				}
				// inform systemd that a reload has started
				updateSystemd(fmt.Sprintf("RELOADING=1\nSTATUS=reloading"))
				var args []string
				var err error
				var file *os.File
				var fileTls *os.File
				files := []*os.File{}
				// __OIO_RAWX_FORK is used for the new process to know
				// it's a forked from a reload
				env := []string{"__OIO_RAWX_FORK=1"}

				// prepare args for the exec.Command call
				if len(os.Args) > 1 {
					args = os.Args[1:]
				}

				// retrieve file descriptor of the HTTP listen socket
				file, err = srv.socket.File()
				if err != nil {
					LogWarning("Unable to retrieve file from HTTP listener, not forking: %v", err)
					continue
				}

				// append the file descriptor to the list
				files = append(files, file)
				// set the environment variable to indicate to the child process
				// which FD to use
				// hardcoding 3 because the first 3 are stdin, stdout and stderr
				// see https://pkg.go.dev/os/exec#Cmd and especially ExtraFiles
				env = append(env, "__OIO_RAWX_FORK_HTTP_FD=3")
				// Addr is used to ensure the address used by the parent is the same as the one the child is
				// supposed to listen to
				env = append(env, fmt.Sprintf("__OIO_RAWX_FORK_HTTP_ADDR=%s", srv.server.Addr))

				// same but for TLS
				if srvTls != nil {
					fileTls, err = srvTls.socket.File()
					if err != nil {
						LogWarning("Unable to retrieve file from HTTPS listener, not forking: %v", err)
						continue
					}
					files = append(files, fileTls)
					env = append(env, "__OIO_RAWX_FORK_HTTPS_FD=4")
					env = append(env, fmt.Sprintf("__OIO_RAWX_FORK_HTTPS_ADDR=%s", srvTls.server.Addr))
				} else {
					// if TLS is not used, ensure to not pass wrong env variables
					os.Unsetenv("__OIO_RAWX_FORK_HTTPS_FD")
					os.Unsetenv("__OIO_RAWX_FORK_HTTPS_ADDR")
				}

				// Launch child process
				cmd := exec.Command(os.Args[0], args...)
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				cmd.ExtraFiles = files
				cmd.Env = append(os.Environ(), env[:]...)
				if err := cmd.Start(); err != nil {
					LogWarning("Fork did not succeed: %s", err)
					continue
				}
				childPid = cmd.Process.Pid
				LogInfo("Started child process %d, waiting for its ready signal", cmd.Process.Pid)
				// notify systemd that the reloading is done (so that systemctl reload can return)
				updateSystemd(fmt.Sprintf("READY=1\nSTATUS=waiting for new rawx process to take over ..."))
			}
		}
	}()
}

func taskProbeRepository(rawx *rawxService, finished chan bool) {
	rawx.probe.ProbeLoop(rawx.path, rawx.getURL(), finished)
}

func main() {
	var err error
	var wg sync.WaitGroup

	// notify systemd with the PID of the new process right before exiting
	// otherwise systemd will take it into account partially and stopping after
	// a reload would be done with a SIGKILL instead of a SIGTERM
	defer func() {
		if childPid > 0 {
			LogInfo("process exit ! (process %d has taken over after reload)", childPid)
			updateSystemd(fmt.Sprintf("MAINPID=%d\nSTATUS=processing request (after reload) ...", childPid))
		} else {
			LogInfo("process exit !")
			updateSystemd("EXIST_STATUS=0\nSTATUS=stopped")
		}
	}()

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

	if opts["log_level"] != "" {
		initVerbosity(LogLevelToSeverity(opts["log_level"]))
	}
	if opts["log_format"] != "" {
		logFormat = opts["log_format"]
	}
	if opts["log_request_format"] != "" {
		requestLogFormat = opts["log_request_format"]
	}
	if opts["log_access_format"] != "" {
		accessLogFormat = opts["log_access_format"]
	}
	if opts["log_event_format"] != "" {
		eventLogFormat = opts["log_event_format"]
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

	InitStatsd(opts["statsd_addr"], opts["statsd_prefix"])

	var graceful_stop_timeout time.Duration = -1
	if v, ok := opts["graceful_stop_timeout"]; ok {
		graceful_stop_timeout, err = time.ParseDuration(v)
		if err != nil {
			log.Fatalf("Invalid graceful_stop_timeout value: %v", err)
		}
	}

	chunkrepo := chunkRepository{}
	namespace := opts["ns"]
	rawxURL := opts["addr"]
	rawxID := opts["id"]
	NotifAllowed = opts.getBool("events", defs.ConfigDefaultEvents)

	accessLogPut = opts.getBool("log_access_put", defs.ConfigDefaultAccessLogPut)
	accessLogGet = opts.getBool("log_access_get", defs.ConfigDefaultAccessLogGet)
	accessLogDel = opts.getBool("log_access_del", defs.ConfigDefaultAccessLogDelete)

	checkNS(namespace)
	checkURL(rawxURL)

	// Init the actual chunk storage
	if err := chunkrepo.sub.init(opts["basedir"]); err != nil {
		LogFatal("Invalid directories: %v", err)
	}
	chunkrepo.sub.hashWidth = opts.getInt("hash_width", chunkrepo.sub.hashWidth)
	chunkrepo.sub.hashDepth = opts.getInt("hash_depth", chunkrepo.sub.hashDepth)
	chunkrepo.sub.shallowCopy = opts.getBool("shallow_copy", chunkrepo.sub.shallowCopy)
	chunkrepo.sub.syncFile = opts.getBool("fsync_file", chunkrepo.sub.syncFile)
	chunkrepo.sub.syncDir = opts.getBool("fsync_dir", chunkrepo.sub.syncDir)
	chunkrepo.sub.fallocateFile = opts.getBool("fallocate", chunkrepo.sub.fallocateFile)
	chunkrepo.sub.openNonBlock = opts.getBool("nonblock", defs.ConfigDefaultOpenNonblock)

	rawx := rawxService{
		ns:           namespace,
		url:          rawxURL,
		tlsUrl:       opts["tls_rawx_url"],
		path:         chunkrepo.sub.root,
		id:           rawxID,
		repo:         chunkrepo,
		bufferSize:   1024 * opts.getInt("buffer_size", defs.UploadBufferSizeDefault/1024),
		checksumMode: defs.ChecksumAlways,
		compression:  opts["compression"],
		probe:        RawxProbe{latch: sync.RWMutex{}, lastIOMsg: "n/a"},
	}

	// Clamp the buffer size to admitted values
	if rawx.bufferSize > defs.UploadBufferSizeMax {
		rawx.bufferSize = defs.UploadBufferSizeMax
	}
	if rawx.bufferSize < defs.UploadBufferSizeMin {
		rawx.bufferSize = defs.UploadBufferSizeMin
	}
	// In case of a misconfiguration
	if rawx.bufferSize < defs.UploadBatchSize {
		rawx.bufferSize = defs.UploadBatchSize
	}

	rawx.uploadBufferPool = utils.NewBufferPool(defs.UploadBufferTotalSizeDefault, rawx.bufferSize)

	// Patch the checksum mode
	if v, ok := opts["checksum"]; ok {
		if v == "smart" {
			rawx.checksumMode = defs.ChecksumSmart
		} else if GetBool(v, true) {
			rawx.checksumMode = defs.ChecksumAlways
		} else {
			rawx.checksumMode = defs.ChecksumNever
		}
	}

	// Patch the fadvise() upon upload
	if v, ok := opts["fadvise_upload"]; ok {
		if strings.ToLower(v) == "cache" {
			chunkrepo.sub.fadviseUpload = defs.ConfigFadviseCache
		} else if strings.ToLower(v) == "nocache" {
			chunkrepo.sub.fadviseUpload = defs.ConfigFadviseNoCache
		} else if GetBool(v, false) {
			chunkrepo.sub.fadviseUpload = defs.ConfigFadviseYes
		}
	}

	// Patch the fadvise() upon download
	if v, ok := opts["fadvise_download"]; ok {
		if strings.ToLower(v) == "cache" {
			chunkrepo.sub.fadviseDownload = defs.ConfigFadviseCache
		} else if strings.ToLower(v) == "nocache" {
			chunkrepo.sub.fadviseDownload = defs.ConfigFadviseNoCache
		} else if GetBool(v, false) {
			chunkrepo.sub.fadviseDownload = defs.ConfigFadviseYes
		}
	}

	if NotifAllowed {
		eventAgent := OioGetEventAgent(namespace)
		if eventAgent == "" {
			LogFatal("Notifier error: no address")
		}

		rawx.notifier, err = MakeNotifier(eventAgent, &opts, &rawx)
		if err != nil {
			LogFatal("Notifier error: %v", err)
		}
	}

	toReadHeader := opts.getInt("timeout_read_header", defs.TimeoutReadHeader)
	toReadRequest := opts.getInt("timeout_read_request", defs.TimeoutReadRequest)
	toWrite := opts.getInt("timeout_write_reply", defs.TimeoutWrite)
	toIdle := opts.getInt("timeout_idle", defs.TimeoutIdle)

	/* need to be duplicated for HTTP and HTTPS */
	srv := httpServer{
		server: http.Server{
			Addr:              rawx.url,
			Handler:           &rawx,
			TLSConfig:         nil,
			ReadHeaderTimeout: time.Duration(toReadHeader) * time.Second,
			ReadTimeout:       time.Duration(toReadRequest) * time.Second,
			WriteTimeout:      time.Duration(toWrite) * time.Second,
			IdleTimeout:       time.Duration(toIdle) * time.Second,
			// The default is at 1MiB but the RAWX never needs that
			MaxHeaderBytes: opts.getInt("headers_buffer_size", 65536),
		},
	}

	tlsSrv := httpServer{
		server: http.Server{
			Addr:              rawx.tlsUrl,
			Handler:           &rawx,
			TLSConfig:         nil,
			ReadHeaderTimeout: time.Duration(toReadHeader) * time.Second,
			ReadTimeout:       time.Duration(toReadRequest) * time.Second,
			WriteTimeout:      time.Duration(toWrite) * time.Second,
			IdleTimeout:       time.Duration(toIdle) * time.Second,
			// The default is at 1MiB but the RAWX never needs that
			MaxHeaderBytes: opts.getInt("headers_buffer_size", 65536),
		},
	}

	flagNoDelay := opts.getBool("nodelay", defs.ConfigDefaultNoDelay)
	flagCork := opts.getBool("cork", defs.ConfigDefaultCork)
	if flagNoDelay || flagCork {
		srv.server.ConnState = func(cnx net.Conn, st http.ConnState) {
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

	keepalive := opts.getBool("keepalive", defs.ConfigDefaultHttpKeepalive)
	srv.server.SetKeepAlivesEnabled(keepalive)
	tlsSrv.server.SetKeepAlivesEnabled(keepalive)
	if opts["tls_rawx_url"] == "" {
		installSigHandlers(&srv, nil, graceful_stop_timeout, &wg)
	} else {
		installSigHandlers(&srv, &tlsSrv, graceful_stop_timeout, &wg)
	}

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
		srv.server.ConnState = func(cnx net.Conn, state http.ConnState) {
			LogDebug("%v %v %v", cnx.LocalAddr(), cnx.RemoteAddr(), state)
		}
		tlsSrv.server.ConnState = func(cnx net.Conn, state http.ConnState) {
			LogDebug("%v %v %v", cnx.LocalAddr(), cnx.RemoteAddr(), state)
		}
	}

	finished := make(chan bool)
	go taskProbeRepository(&rawx, finished)

	// run HTTP server
	if err := Run(&wg, &srv, "", ""); err != nil {
		log.Fatalf("Unable to start HTTP server on %s: %v", srv.server.Addr, err.Error())
	}

	// run TLS server
	if opts["tls_rawx_url"] != "" {
		if err := Run(&wg, &tlsSrv, opts["tls_cert_file"], opts["tls_key_file"]); err != nil {
			log.Fatalf("Unable to start HTTPS server on %s: %v", tlsSrv.server.Addr, err.Error())
		}
	}

	// if process has been launched from a graceful restart
	// kill the parent process gracefuly
	if os.Getenv("__OIO_RAWX_FORK") != "" {
		ppid := syscall.Getppid()
		LogInfo("child process launched with success, graceful stop the parent process (%d)", ppid)
		syscall.Kill(ppid, syscall.SIGTERM)
	} else {
		// it is a initial start
		// let's inform systemd that the process is up and running
		updateSystemd(fmt.Sprintf("READY=1\nSTATUS=processing request (initial start) ..."))
	}

	// backup NOTIFY_SOCKET (systemd)
	notify_socket := os.Getenv("NOTIFY_SOCKET")

	// ensure the process environment is cleanup for next graceful restart
	os.Clearenv()

	// push back NOTIFY_SOCKET if set
	if notify_socket != "" {
		os.Setenv("NOTIFY_SOCKET", notify_socket)
	}

	// wait for HTTP and TLS server to stop before clean exit
	wg.Wait()

	finished <- true
	if NotifAllowed {
		rawx.notifier.Stop()
	}

	logger.close()
}
