#ifndef __RAINX_H_CLIENT__
#define __RAINX_H_CLIENT__

#include "./gs_internals.h"

#define RAINX_UPLOAD "PUT"
#define RAINX_DOWNLOAD "GET"

gboolean stg_pol_is_rainx(namespace_info_t *ni, const gchar *stgpol);
gboolean stg_pol_rainx_get_param(namespace_info_t *ni, const gchar *stgpol, const gchar *param, gint64 *p_val);

GSList* rainx_get_spare_chunks(gs_container_t *container, gchar *content_path, gint64 count,
		gint64 distance, GSList *notin_list, GSList *broken_rawx_list, gs_error_t **err);

addr_info_t* get_rainx_from_conscience(const gchar *nsname, GError **error);


gboolean rainx_ask_reconstruct(struct dl_status_s *dl_status, gs_content_t *content, GSList *aggregated_chunks,
		GSList *filtered, GSList *beans, GSList *broken_rawx_list, GHashTable *failed_chunks,
		const gchar *storage_policy, gs_error_t **err);

#endif /* __RAINX_H_CLIENT__ */
