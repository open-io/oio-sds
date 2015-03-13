/*
OpenIO SDS rainx
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__rainx__rainx_http_tools_h
# define OIO_SDS__rainx__rainx_http_tools_h 1

#include <mod_dav.h>

#include <rainx/rainx_repository.h>

#define MAX_REPLY_HEADER_SIZE 8192
#define REPLY_BUFFER_SIZE 131072
#define REQUEST_BUFFER_SIZE 131072

/*
 * Sends a request to a rawx.
 *
 * stream : The stream to get the APR pool from
 * remote_url : The remote Rawx full URL with the content hexid (ip:port/hexid)
 * req_type : The type of the request (PUT/GET/DELETE)
 * data : The data to send (nullable)
 * data_length : The length of the data
 * reply : The response from the Rawx (nullable)
 *
 * Returns : The APR status
 **/
apr_status_t
rainx_http_req(struct req_params_store* rps);

#endif /*OIO_SDS__rainx__rainx_http_tools_h*/