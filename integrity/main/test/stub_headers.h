/*
OpenIO SDS integrity
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

#ifndef OIO_SDS__integrity__main__test__stub_headers_h
# define OIO_SDS__integrity__main__test__stub_headers_h 1

#include "../lib/alert.h"
#include <rawx_client.h>
typedef gboolean  (*test_dept_alert_fun)(const gchar* , int , const gchar* );
void test_dept_alert_set(test_dept_alert_fun f);
gboolean  test_dept_proxy_alert(const gchar* domain, int criticity, const gchar* message);
typedef gboolean  (*test_dept_rawx_client_get_directory_data_fun)(rawx_session_t * , hash_sha256_t , struct content_textinfo_s *, struct chunk_textinfo_s *, GError ** );
void test_dept_rawx_client_get_directory_data_set(test_dept_rawx_client_get_directory_data_fun f);
gboolean  test_dept_proxy_rawx_client_get_directory_data(rawx_session_t * session, hash_sha256_t chunk_id, struct content_textinfo_s *content, struct chunk_textinfo_s *chunk, GError ** error);

#endif /*OIO_SDS__integrity__main__test__stub_headers_h*/