/*
OpenIO SDS rawx-apache2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#ifndef OIO_SDS__rawx_apache2__src__rawx_bucket_h
# define OIO_SDS__rawx_apache2__src__rawx_bucket_h 1

#include <apr.h>
#include <apr_buckets.h>

struct apr_bucket_type_t chunk_bucket_type;

void chunk_bucket_destroy(void *d);

void chunk_bucket_free_noop(void *d);

apr_status_t chunk_bucket_read(apr_bucket *b, const char **str, apr_size_t *len, apr_read_type_e block);

apr_status_t chunk_bucket_split(apr_bucket *e, apr_size_t point);

apr_status_t chunk_bucket_copy(apr_bucket *e, apr_bucket **c);

#endif /*OIO_SDS__rawx_apache2__src__rawx_bucket_h*/