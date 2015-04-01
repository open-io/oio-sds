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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.rawx_maintenance"
#endif

#include "metautils.h"

void
chunk_textinfo_free_content(struct chunk_textinfo_s *cti)
{
	if (!cti)
		return;
	g_free(cti->id);
	g_free(cti->path);
	g_free(cti->size);
	g_free(cti->hash);
	g_free(cti->position);
	g_free(cti->metadata);
	g_free(cti->container_id);
	memset(cti, 0x00, sizeof(struct chunk_textinfo_s));
}

void
content_textinfo_free_content(struct content_textinfo_s *cti)
{
	if (!cti)
		return;
	g_free(cti->path);
	g_free(cti->size);
	g_free(cti->metadata);
	g_free(cti->system_metadata);
	g_free(cti->chunk_nb);
	g_free(cti->container_id);
	g_free(cti->storage_policy);
	g_free(cti->rawx_list);
	g_free(cti->spare_rawx_list);
	g_free(cti->version);
	memset(cti, 0x00, sizeof(struct content_textinfo_s));
}

