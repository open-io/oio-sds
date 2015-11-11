/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <string.h>

#include <glib.h>

#include "core/oiostr.h"
#include "rawx.h"

void
chunk_textinfo_free_content(struct chunk_textinfo_s *cti)
{
	if (!cti)
		return;
	oio_str_clean (&cti->id);
	oio_str_clean (&cti->size);
	oio_str_clean (&cti->hash);
	oio_str_clean (&cti->position);
	oio_str_clean (&cti->metadata);
}

void
content_textinfo_free_content(struct content_textinfo_s *cti)
{
	if (!cti)
		return;
	oio_str_clean (&cti->container_id);

	oio_str_clean (&cti->content_id);
	oio_str_clean (&cti->path);
	oio_str_clean (&cti->version);
	oio_str_clean (&cti->size);
	oio_str_clean (&cti->chunk_nb);
	oio_str_clean (&cti->storage_policy);

	oio_str_clean (&cti->rawx_list);
	oio_str_clean (&cti->spare_rawx_list);
}

