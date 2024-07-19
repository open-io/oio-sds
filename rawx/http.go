package main

// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2023-2024 OVH SAS
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

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"

	"openio-sds/rawx/logger"
)

func Run(wg *sync.WaitGroup, srv *httpServer, tls_cert_file string, tls_key_file string) error {
	var protocol string
	var fd int64 = -1
	var addr string
	var err error
	var listener net.Listener

	if tls_cert_file != "" && tls_key_file != "" {
		protocol = "HTTPS"
	} else {
		protocol = "HTTP"
	}

	fdEnvVar := os.Getenv(fmt.Sprintf("__OIO_RAWX_FORK_%s_FD", protocol))
	if fdEnvVar != "" {
		fd, err = strconv.ParseInt(fdEnvVar, 10, 64)
		if err != nil {
			logger.LogWarning("[%s] Error while parsing __OIO_RAWX_FORK_%s_FD env variable: %v", protocol, protocol, err)
			fd = -1
		}
	}
	if fd > -1 {
		addr = os.Getenv(fmt.Sprintf("__OIO_RAWX_FORK_%s_ADDR", protocol))
		if addr == "" || addr != srv.server.Addr {
			logger.LogWarning("[%s] graceful restart asked but Addr changed, use a new socket (old=%s new=%s)", protocol, addr, srv.server.Addr)
			file := os.NewFile(uintptr(fd), "")
			file.Close()
			fd = -1
		}
	}

	if fd > -1 {
		logger.LogInfo("[%s] About to use fd %d to listen on %s", protocol, fd, srv.server.Addr)
		file := os.NewFile(uintptr(fd), "")
		listener, err = net.FileListener(file)
		if err != nil {
			fd = -1
			return fmt.Errorf("[%s] Unable to listen (%s) using existing FD %d: %v", protocol, srv.server.Addr, fd, err)
		}
	}
	if fd == -1 {
		listener, err = net.Listen("tcp", srv.server.Addr)
		if err != nil {
			return err
		}
	}
	srv.socket = listener.(*net.TCPListener)

	wg.Add(1)

	go func() {
		defer wg.Done()

		var err error

		logger.LogInfo("[%s] About to serve on %s", protocol, srv.server.Addr)
		if tls_cert_file != "" && tls_key_file != "" {
			err = srv.server.ServeTLS(listener, tls_cert_file, tls_key_file)
		} else {
			err = srv.server.Serve(listener)
		}

		if err != http.ErrServerClosed {
			logger.LogWarning("[%s] Unable to start server: %v", protocol, err.Error())
		}

		logger.LogInfo("[%s] server stopped on %s", protocol, srv.server.Addr)
	}()

	return nil
}
