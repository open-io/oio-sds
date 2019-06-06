/*
OpenIO SDS fabx
Copyright (C) 2018-2019 CEA "CEA <info@cea.fr>"
Copyright (C) 2018-2019 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_FABX_CLIENT_H
#define OIO_FABX_CLIENT_H

#include <glib.h>
#include <core/oio_core.h>

/* ------------------------------------------------------------------------- */

struct oio_fabx_upload_s;

struct oio_fabx_upload_s* oio_fabx_upload_create(
		struct oio_url_s *url);

void oio_fabx_upload_close(
		struct oio_fabx_upload_s *ul);

void oio_fabx_upload_target(
		struct oio_fabx_upload_s *ul,
		const char *host_port,
		const char *chunk_id);

void oio_fabx_upload_push(
		struct oio_fabx_upload_s *ul,
		GBytes *block);

void oio_fabx_upload_finalize(
		struct oio_fabx_upload_s *ul);

/* ------------------------------------------------------------------------- */

struct oio_fabx_download_s;

struct oio_fabx_download_s* oio_fabx_download_create(
		struct oio_url_s *url);

void oio_fabx_download_close(
		struct oio_fabx_download_s *ul);

void oio_fabx_download_source(
		struct oio_fabx_download_s *ul,
		const char *host_port,
		const char *chunk_id,
		guint64 offset,
		guint64 size);

GError* oio_fabx_download_consume(
		struct oio_fabx_download_s *ul,
		GBytes **block);

#endif  /* OIO_FABX_CLIENT_H */
