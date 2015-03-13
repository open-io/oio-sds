/*
OpenIO SDS meta2v2
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

#ifndef OIO_SDS__meta2v2__meta2_test_common_h
# define OIO_SDS__meta2v2__meta2_test_common_h 1

struct meta2_backend_s;
struct hc_url_s;

/**
 * Function taking a `struct meta2_backend_s *` as parameter
 * and returning nothing.
 */
typedef void (*repo_test_f) (struct meta2_backend_s *m2);

/**
 * Function taking a `struct meta2_backend_s *` and
 * a `struct hc_url_s *` as parameters and returning nothing.
 */
typedef void (*container_test_f) (struct meta2_backend_s *m2,
		struct hc_url_s *url);

void debug_beans_list(GSList *l);
void debug_beans_array(GPtrArray *v);

GSList* create_alias(struct meta2_backend_s *m2b, struct hc_url_s *url,
		const gchar *polname);

/**
 * Run a function on a simulated backend.
 */
void repo_wrapper(const gchar *ns, repo_test_f fr);

/**
 * Run a function on a simulated backend with one container.
 */
void container_wrapper(container_test_f cf);

#endif /*OIO_SDS__meta2v2__meta2_test_common_h*/