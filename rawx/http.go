package main

// OpenIO SDS Go rawx
// Copyright (C) 2015-2020 OpenIO SAS
// Copyright (C) 2023 OVH SAS
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
	"log"
	"net"
	"net/http"
	"sync"
	"golang.org/x/net/netutil"
)

func Run(srv *http.Server, tlsSrv *http.Server, opts optionsMap) error {
	errs := make(chan error)
	var servers sync.WaitGroup
	max_connections := opts.getInt("max_connections", maxConnectionsDefault)

	servers.Add(1)
	go func() {
		defer servers.Done()
		log.Printf("Starting HTTP service on %s, max_connections=%d",
				srv.Addr, max_connections)
		listener, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			errs <- err
		} else {
			listener = netutil.LimitListener(listener, max_connections)
			defer listener.Close()
			if err := srv.Serve(listener); err != http.ErrServerClosed {
				errs <- err
			} else {
				errs <- nil
			}
		}

		log.Printf("HTTP service on %s stopped", srv.Addr)
	}()

	if len(opts["tls_rawx_url"]) > 0 {
		servers.Add(1)
		// Starting HTTPS server
		go func() {
			defer servers.Done()
			log.Printf("Starting HTTPS service on %s, max_connections=%d",
					tlsSrv.Addr, max_connections)
			tls_listener, err := net.Listen("tcp", tlsSrv.Addr)
			if err != nil {
				errs <- err
			} else {
				tls_listener = netutil.LimitListener(tls_listener, max_connections)
				defer tls_listener.Close()
				if err := tlsSrv.ServeTLS(tls_listener, opts["tls_cert_file"], opts["tls_key_file"]);
						err != http.ErrServerClosed {
					errs <- err
				} else {
					errs <- nil
				}
			}
			log.Printf("HTTPS service on %s stopped", tlsSrv.Addr)
		}()
	}

	if err := <-errs; err != nil {
		log.Printf("Could not start serving service due to (error: %s)", err)
		return err
	}

	servers.Wait()
	return nil
}
