#ifndef __RAINX_H_CLIENT__
#define __RAINX_H_CLIENT__

#include "./gs_internals.h"

#define RAINX_UPLOAD "PUT"
#define RAINX_DOWNLOAD "GET"

gboolean stg_pol_is_rainx(namespace_info_t *ni, const gchar *stgpol);
gboolean stg_pol_rainx_get_param(namespace_info_t *ni, const gchar *stgpol, const gchar *param, gint64 *p_val);

GSList* rainx_get_spare_chunks(gs_container_t *container, gchar *content_path, gint64 count,
		gint64 distance, GSList *notin_list, GSList *broken_rawx_list, gs_error_t **err);

void rainx_init_content_hash(void);
content_hash_t* rainx_finalize_content_hash(void);

addr_info_t* get_rainx_from_conscience(const gchar *nsname, GError **error);

gs_status_t rainx_upload(GSList *chunk_list, gs_content_t *hollow_content, addr_info_t *rainx_addr,
		gs_input_f input, void *user_data, GByteArray *system_metadata, GSList **returned_chunk_list,
		const gchar *storage_policy, guint32 current_metachunk_pos, guint metachunksize, GError **err);

gboolean rainx_ask_reconstruct(struct dl_status_s *dl_status, gs_content_t *content, GSList *aggregated_chunks,
		GSList *filtered, GSList *beans, GSList *broken_rawx_list, GHashTable *failed_chunks,
		const gchar *storage_policy, gs_error_t **err);

#endif /* __RAINX_H_CLIENT__ */
