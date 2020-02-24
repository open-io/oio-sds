package main

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

import (
	"log"
	"net/http"
)

func Run(srv *http.Server, tlsSrv *http.Server,
	opts optionsMap) error {
	errs := make(chan error)

	go func() {
		log.Printf("Starting HTTP service on %s ...", srv.Addr)
		if err := srv.ListenAndServe(); err != nil {
			errs <- err
		}

	}()

	if len(opts["tls_rawx_url"]) > 0 {
		// Starting HTTPS server
		go func() {
			log.Printf("Starting HTTPS service on %s ...", tlsSrv.Addr)
			if err := tlsSrv.ListenAndServeTLS(opts["tls_cert_file"], opts["tls_key_file"]); err != nil {
				errs <- err
			}
		}()
	}

	if err := <-errs; err != nil {
		log.Printf("Could not start serving service due to (error: %s)", err)
		return err
	}

	return nil
}
