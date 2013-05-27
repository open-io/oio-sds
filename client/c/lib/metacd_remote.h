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

#ifndef __METACD_CLIENT_H__
# define __METACD_CLIENT_H__

# include <glib.h>
# include <metatypes.h>


struct metacd_s {
	char path[1024];
	char nsName[LIMIT_LENGTH_NSNAME];
	struct {
		gint cnx;
		gint op;
	} timeout;
};


struct metacd_connection_info_s {
	struct metacd_s metacd;
	guint8 *cnx_id;
	gsize   cnx_id_size;
};

const gchar *make_metacd_path(const gchar *content_path, const gchar *content_version);
const gchar *make_metacd_path2(const gchar *content_path, content_version_t content_version);
void destroy_metacd_path(const gchar *metacd_path);

GSList* metacd_remote_get_meta0(const struct metacd_connection_info_s *mi,
	GError **err);

GSList* metacd_remote_get_meta1 (const struct metacd_connection_info_s *mi,
	const container_id_t cID, int ro, GSList *exclude, GError **err);

gboolean metacd_remote_set_meta1_master (const struct metacd_connection_info_s *mi, const container_id_t cid,
	const char *master, GError **e);

GSList* metacd_remote_get_meta2 (const struct metacd_connection_info_s *mi,
	const container_id_t cID, GError **err);

gboolean metacd_remote_decache (const struct metacd_connection_info_s *mi,
	const container_id_t cID, GError **err);

gboolean metacd_remote_decache_all (const struct metacd_connection_info_s *mi,
	GError **err);


struct meta2_raw_content_s* metacd_remote_get_content (const struct metacd_connection_info_s *mi,
	const container_id_t cID, const gchar *content, GError **err);

gboolean metacd_remote_forget_content(struct metacd_connection_info_s *mi,
	const container_id_t cID, const gchar *path, GError **err);

gboolean metacd_remote_save_content(struct metacd_connection_info_s *mi, struct meta2_raw_content_s *content, GError **err);

gboolean metacd_remote_flush_content(struct metacd_connection_info_s *mi,
	GError **err);


#endif /*__METACD_CLIENT_H__*/
