/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "metautils.rawx_maintenance"
#endif

#include <string.h>
#include <glib.h>
#include "./metatypes.h"
#include "./metautils.h"

void
chunk_textinfo_free_content(struct chunk_textinfo_s *cti)
{
	if (!cti)
		return;
	if (cti->id)
		g_free(cti->id);
	if (cti->path)
		g_free(cti->path);
	if (cti->size)
		g_free(cti->size);
	if (cti->hash)
		g_free(cti->hash);
	if (cti->position)
		g_free(cti->position);
	if (cti->metadata)
		g_free(cti->metadata);
	if (cti->container_id)
		g_free(cti->container_id);
	memset(cti, 0x00, sizeof(struct chunk_textinfo_s));
}


void
content_textinfo_free_content(struct content_textinfo_s *cti)
{
	if (!cti)
		return;
	if (cti->path)
		g_free(cti->path);
	if (cti->size)
		g_free(cti->size);
	if (cti->metadata)
		g_free(cti->metadata);
	if (cti->system_metadata)
		g_free(cti->system_metadata);
	if (cti->chunk_nb)
		g_free(cti->chunk_nb);
	if (cti->container_id)
		g_free(cti->container_id);
	memset(cti, 0x00, sizeof(struct content_textinfo_s));
}


int
chunk_is_last(struct chunk_textinfo_s *chunk, struct content_textinfo_s *content)
{
	gint32 i_pos, i_nbr;

	if (!chunk || !content)
		return 0;
	if (!chunk->position || !content->chunk_nb)
		return 0;
	i_pos = g_ascii_strtoll(chunk->position, NULL, 10);
	i_nbr = g_ascii_strtoll(content->chunk_nb, NULL, 10);
	return (i_pos + 1 >= i_nbr);
}
