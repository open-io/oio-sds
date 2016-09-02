/*
OpenIO SDS proxy
Copyright (C) 2016 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <meta0v2/meta0_remote.h>
#include <meta0v2/meta0_utils.h>

#include "common.h"
#include "actions.h"

static GString* _m0_mapping_from_m1_list(GSList *m1_list) {
	gboolean first = TRUE;
	GString *out = g_string_sized_new(65536 * 20);
	GPtrArray *array = meta0_utils_list_to_array(m1_list);

	g_string_append_c(out, '{');
	for (guint i = 0; i < array->len; i++) {
		gchar **v;
		if ((v = array->pdata[i]) != NULL) {
			if (!first)
				g_string_append_c(out, ',');
			guint16 p = i;
			gboolean first2 = TRUE;
			g_string_append_printf(out, "\"%04X\":[", p);
			for (gchar **m1 = v; m1 && *m1; m1++) {
				if (!first2)
					g_string_append_c(out, ',');
				first2 = FALSE;
				g_string_append_printf(out, "\"%s\"", *m1);
			}
			g_string_append_c(out, ']');
			first = FALSE;
		}
	}
	g_string_append_c(out, '}');

	meta0_utils_array_clean(array);
	return out;
}

// TODO: factorize the two following functions
enum http_rc_e action_admin_meta0_list(struct req_args_s *args) {
	GError *err = NULL;
	GSList *m0_lst = NULL;
	GSList *m1_lst = NULL;
	GString *json = NULL;

	err = conscience_get_services(NS(), NAME_SRVTYPE_META0, FALSE, &m0_lst);
	if (!err) {
		for (GSList *l = m0_lst; l; l = l->next) {
			g_clear_error(&err);
			service_info_t *m0 = l->data;
			gchar m0_url[STRLEN_ADDRINFO] = {0};
			grid_addrinfo_to_string(&(m0->addr), m0_url, sizeof(m0_url));

			err = meta0_remote_get_meta1_all(m0_url, &m1_lst);

			if (!err || !CODE_IS_NETWORK_ERROR(err->code))
				break;
		}
		g_slist_free_full(m0_lst, (GDestroyNotify)service_info_clean);
	}

	if (m1_lst) {
		json = _m0_mapping_from_m1_list(m1_lst);
		meta0_utils_list_clean(m1_lst);
		return _reply_json(args, HTTP_CODE_OK, "OK", json);
	}
	return _reply_common_error(args, err);
}

enum http_rc_e action_admin_meta0_force(struct req_args_s *args) {
	GError *err = NULL;
	GSList *m0_lst = NULL;

	err = conscience_get_services(NS(), NAME_SRVTYPE_META0, FALSE, &m0_lst);
	if (!err) {
		for (GSList *l = m0_lst; l; l = l->next) {
			g_clear_error(&err);
			service_info_t *m0 = l->data;
			gchar m0_url[STRLEN_ADDRINFO] = {0};
			grid_addrinfo_to_string(&(m0->addr), m0_url, sizeof(m0_url));

			err = meta0_remote_force(m0_url, (gchar*) args->rq->body->data);

			if (!err) {
				err = meta0_remote_cache_refresh(m0_url);
				break;
			} else if (!CODE_IS_NETWORK_ERROR(err->code)) {
				break;
			}
		}
		g_slist_free_full(m0_lst, (GDestroyNotify)service_info_clean);
	}
	if (err)
		return _reply_common_error(args, err);
	return _reply_nocontent(args);
}
