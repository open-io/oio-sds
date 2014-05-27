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
