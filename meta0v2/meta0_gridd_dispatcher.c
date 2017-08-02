/*
OpenIO SDS meta0v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#include <metautils/lib/metautils.h>
#include <server/transport_gridd.h>

#include "meta0_backend.h"
#include "meta0_utils.h"
#include "meta0_gridd_dispatcher.h"
#include "internals.h"

struct meta0_disp_s {
	struct meta0_backend_s *m0;
	gchar *ns_name;
	GByteArray *encoded;
	GMutex lock;
	gboolean reload_requested;
};

/* ------------------------------------------------------------------------- */

static GTree* urlv_to_tree(const guint8 *prefix, gchar **urlv) {
	GTree *tree = meta0_utils_tree_create();
	if (urlv) for (gchar **u=urlv; *u ;u++)
		meta0_utils_tree_add_url(tree, prefix, *u);
	g_strfreev(urlv);
	return tree;
}

static GError * extract_prefix(MESSAGE msg, const gchar *n, gboolean mandatory,
		guint8 *prefix) {
	gsize f_size;
	void *f = metautils_message_get_field(msg, n, &f_size);
	if (!f) {
		if (mandatory)
			return NEWERROR(CODE_BAD_REQUEST, "Missing field '%s'", n);
		return NULL;
	}
	if (f_size != 2)
		return NEWERROR(CODE_BAD_REQUEST, "Invalid field size '%s'", n);

	prefix[0] = ((guint8*)f)[0];
	prefix[1] = ((guint8*)f)[1];
	GRID_TRACE("Got header [%s] <- [%02X%02X]", n, prefix[0], prefix[1]);
	return NULL;
}

/* -------------------------------------------------------------------------- */

static GByteArray* _encode_meta0_list(GSList *list) {
	GByteArray *encoded = meta0_info_marshall_gba(list, NULL);
	meta0_utils_list_clean(list);
	return encoded;
}

static GByteArray* _encode_meta0_array(GPtrArray *array) {
	GSList *list = meta0_utils_array_to_list(array);
	meta0_utils_array_clean(array);
	return _encode_meta0_list(list);
}

static GByteArray* _encode_meta0_tree(GTree *tree) {
	GSList *list = meta0_utils_tree_to_list(tree);
	g_tree_unref(tree);
	return _encode_meta0_list(list);
}

static GByteArray* _get_encoded(struct meta0_disp_s *m0disp) {
	GError *err = NULL;
	GByteArray *encoded = NULL;

	g_mutex_lock(&m0disp->lock);
	if (!m0disp->encoded || m0disp->reload_requested) {
		GPtrArray *array = NULL;
		err = meta0_backend_get_all(m0disp->m0, &array);
		if (!err)
			m0disp->encoded = _encode_meta0_array(array);
		m0disp->reload_requested=FALSE;
	}
	if (m0disp->encoded)
		encoded = g_byte_array_ref(m0disp->encoded);
	g_mutex_unlock(&m0disp->lock);

	if (err) {
		GRID_WARN("META0 reload failed : (%d) %s", err->code, err->message);
		g_clear_error(&err);
	}
	return encoded;
}

static void _reload(struct meta0_disp_s *m0disp) {
	GError *err = NULL;
	GPtrArray *array = NULL;

	g_mutex_lock(&m0disp->lock);
	err = meta0_backend_get_all(m0disp->m0, &array);
	m0disp->reload_requested = FALSE;
	if (!err) {
		if (m0disp->encoded)
			g_byte_array_unref(m0disp->encoded);
		m0disp->encoded = _encode_meta0_array(array);
	}
	g_mutex_unlock(&m0disp->lock);

	if (err) {
		GRID_WARN("META0 reload failed : (%d) %s", err->code, err->message);
		g_clear_error(&err);
	}
}

/* -------------------------------------------------------------------------- */

static gboolean
meta0_dispatch_v1_GETONE(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored UNUSED)
{
	guint8 prefix[2] = {0,0};

	GError *err = extract_prefix(reply->request, NAME_MSGKEY_PREFIX, TRUE, prefix);
	if (NULL != err) {
		reply->send_error(CODE_BAD_REQUEST, err);
	} else {
		reply->subject("%02X%02X", prefix[0], prefix[1]);
		gchar **urlv = NULL;
		err = meta0_backend_get_one(m0disp->m0, prefix, &urlv);
		if (NULL != err) {
			g_prefix_error(&err, "Backend error: ");
			reply->send_error(CODE_INTERNAL_ERROR, err);
		} else {
			reply->add_body(_encode_meta0_tree(urlv_to_tree(prefix, urlv)));
			reply->send_reply(CODE_FINAL_OK, "OK");
		}
	}
	return TRUE;
}

static gboolean
meta0_dispatch_v1_GETALL(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored UNUSED)
{
	reply->add_body(_get_encoded(m0disp));
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
meta0_dispatch_v1_RELOAD(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored UNUSED)
{
	GError *err;

	if (NULL != (err = meta0_backend_reload(m0disp->m0))) {
		g_prefix_error(&err, "Backend error: ");
		reply->send_error(0, err);
		return TRUE;
	}

	_reload(m0disp);
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
meta0_dispatch_v1_RESET(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored UNUSED)
{
	gboolean flag_local = metautils_message_extract_flag (reply->request,
			NAME_MSGKEY_LOCAL, FALSE);

	GError *err = meta0_backend_reset(m0disp->m0, flag_local);
	if (NULL != err) {
		g_prefix_error(&err, "Backend error: ");
		reply->send_error(0, err);
		return TRUE;
	}

	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
meta0_dispatch_v1_FORCE(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored UNUSED)
{
	gchar *mapping = NULL;
	GError *err = metautils_message_extract_body_string(reply->request, &mapping);
	if (err != NULL) {
		reply->send_error(CODE_BAD_REQUEST, err);
		return TRUE;
	}

	if (!mapping || !*mapping) {
		err = NEWERROR(CODE_BAD_REQUEST, "Empty mapping provided");
	} else {
		err = meta0_backend_fill_from_json(m0disp->m0, mapping);
	}

	g_free(mapping);

	if (!err)
		reply->send_reply(CODE_FINAL_OK, "OK");
	else
		reply->send_error(0, err);

	return TRUE;
}

/* ------------------------------------------------------------------------- */

typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);

const struct gridd_request_descr_s *meta0_gridd_get_requests(void) {
	static struct gridd_request_descr_s descriptions[] = {
		{NAME_MSGNAME_M0_GETALL,              (hook) meta0_dispatch_v1_GETALL,  NULL},
		{NAME_MSGNAME_M0_GETONE,              (hook) meta0_dispatch_v1_GETONE,  NULL},
		{NAME_MSGNAME_M0_RELOAD,              (hook) meta0_dispatch_v1_RELOAD,  NULL},
		{NAME_MSGNAME_M0_RESET,               (hook) meta0_dispatch_v1_RESET,   NULL},
		{NAME_MSGNAME_M0_FORCE,               (hook) meta0_dispatch_v1_FORCE,   NULL},
		{NULL, NULL, NULL}
	};

	return descriptions;
}

void meta0_gridd_requested_reload(struct meta0_disp_s *m0disp) {
	m0disp->reload_requested = TRUE;
	meta0_backend_reload_requested(m0disp->m0);
}

struct meta0_disp_s* meta0_gridd_get_dispatcher(struct meta0_backend_s *m0,
		const char* ns_name) {
	struct meta0_disp_s *result = g_malloc0(sizeof(*result));
	result->ns_name = g_strdup(ns_name);
	result->m0 = m0;
	g_mutex_init(&result->lock);

	meta0_gridd_requested_reload(result);
	return result;
}

void meta0_gridd_free_dispatcher(struct meta0_disp_s *m0disp) {
	if (!m0disp)
		return;
	if (m0disp->encoded)
		g_byte_array_unref(m0disp->encoded);
	oio_str_clean(&m0disp->ns_name);
	g_mutex_clear(&m0disp->lock);
	g_free(m0disp);
}
