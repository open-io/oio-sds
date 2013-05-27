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

#ifndef __CHUNKINFO_NEON_SESSION_H__
# define __CHUNKINFO_NEON_SESSION_H__
# include <glib.h>
# include "./gs_internals.h"

/* delete one remote chunk */
gs_status_t rawx_delete (gs_chunk_t *chunk, GError **err);

/*  */
gs_status_t rawx_upload_v2 (gs_chunk_t *chunk, GError **err,
	gs_input_f input, void *user_data, GByteArray *user_metadata, GByteArray *system_metadata, gboolean process_md5);

/*  */
gs_status_t rawx_upload (gs_chunk_t *chunk, GError **err,
	gs_input_f input, void *user_data, GByteArray *system_metadata, gboolean process_md5);

void clean_after_upload(void *user_data);
void finalize_content_hash(void);
content_hash_t *get_content_hash(void);

/*  */
gboolean rawx_download (gs_chunk_t *chunk, GError **err, struct dl_status_s *status);

int rawx_init (void);

gboolean rawx_update_chunk_attr(struct meta2_raw_chunk_s *c, const char *name, const char *val, GError **err);

#endif /*__CHUNKINFO_NEON_SESSION_H__*/
