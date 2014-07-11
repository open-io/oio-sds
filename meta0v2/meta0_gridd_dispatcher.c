#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta0.disp"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <server/grid_daemon.h>
#include <server/transport_gridd.h>

#include "./meta0_backend.h"
#include "./meta0_utils.h"
#include "./meta0_prefixassign.h"
#include "./meta0_gridd_dispatcher.h"
#include "./internals.h"

static GQuark gquark_log = 0;

struct meta0_disp_s
{
	struct meta0_backend_s *m0;
	struct zk_manager_s *m0zkmanager;
	gchar *ns_name;
	GMutex *lock;
	GByteArray *encoded;
	gboolean reload_requested;
};

/* ------------------------------------------------------------------------- */

static GTree*
urlv_to_tree(const guint8 *prefix, gchar **urlv)
{
	gchar **u;
	GTree *tree = meta0_utils_tree_create();
	for (u=urlv; u && *u ;u++)
		meta0_utils_tree_add_url(tree, prefix, *u);
	g_strfreev(urlv);
	return tree;
}

static GError *
extract_prefix(struct message_s *msg, const gchar *n,
		gboolean mandatory, guint8 *prefix)
{
	void *f;
	gsize f_size;

	if (0 >= message_get_field(msg, n, strlen(n), &f, &f_size, NULL)) {
		if (mandatory)
			return g_error_new(gquark_log, 400, "Missing field '%s'", n);
		return NULL;
	}
	if (f_size != 2)
		return g_error_new(gquark_log, 400, "Invalid field size '%s'", n);

	prefix[0] = ((guint8*)f)[0];
	prefix[1] = ((guint8*)f)[1];
	GRID_TRACE("Got header [%s] <- [%02X%02X]", n, prefix[0], prefix[1]);
	return NULL;
}

static gboolean
extract_nocheck(struct message_s *msg)
{
	void *f;
        gsize f_size;

	if (0 >= message_get_field(msg, "NOCHECK", sizeof("NOCHECK")-1, &f, &f_size, NULL)) {
		return TRUE;
	}

	return FALSE;
}

/* -------------------------------------------------------------------------- */

static GByteArray*
_encode_meta0_list(GSList *list)
{
	GByteArray *encoded = meta0_info_marshall_gba(list, NULL);
	meta0_utils_list_clean(list);
	return encoded;
}

static GByteArray*
_encode_meta0_array(GPtrArray *array)
{
	GSList *list = meta0_utils_array_to_list(array);
	meta0_utils_array_clean(array);
	return _encode_meta0_list(list);
}

static GByteArray*
_encode_meta0_tree(GTree *tree)
{
	GSList *list = meta0_utils_tree_to_list(tree);
	g_tree_unref(tree);
	return _encode_meta0_list(list);
}

static GByteArray*
_get_encoded(struct meta0_disp_s *m0disp)
{
	GError *err = NULL;
	GByteArray *encoded = NULL;

	g_mutex_lock(m0disp->lock);
	if (!m0disp->encoded || m0disp->reload_requested) {
		GPtrArray *array = NULL;
		err = meta0_backend_get_all(m0disp->m0, &array);
		if (!err)
			m0disp->encoded = _encode_meta0_array(array);
		m0disp->reload_requested=FALSE;
	}
	if (m0disp->encoded)
		encoded = g_byte_array_ref(m0disp->encoded);
	g_mutex_unlock(m0disp->lock);

	if (err) {
		GRID_WARN("META0 reload failed : (%d) %s", err->code, err->message);
		g_clear_error(&err);
	}
	return encoded;
}

static GByteArray*
_encode_meta1ref(struct meta0_disp_s *m0disp)
{
	GError *err = NULL;
	GByteArray *encoded = NULL;
	GPtrArray *array = NULL;

	g_mutex_lock(m0disp->lock);
	err = meta0_backend_get_all_meta1_ref(m0disp->m0, &array);
	if(!err) {
		guint i, max;
		gchar **v0 = g_malloc0(sizeof(gchar*)* (array->len + 1));
		for (i=0,max=array->len; i<max ;i++) {
			v0[i] = g_strdup(array->pdata[i]);
		}
		v0[max]=NULL;

		encoded=metautils_encode_lines(v0);
	}
	g_mutex_unlock(m0disp->lock);

	meta0_utils_array_meta1ref_clean(array);

	if (err) {
		GRID_WARN("META0 reload failed : (%d) %s", err->code, err->message);
		g_clear_error(&err);
	}
	return encoded;
}

static void
_reload(struct meta0_disp_s *m0disp)
{
	GError *err = NULL;
	GPtrArray *array = NULL;

	g_mutex_lock(m0disp->lock);
	err = meta0_backend_get_all(m0disp->m0, &array);
	m0disp->reload_requested = FALSE;
	if (!err) {
		if (m0disp->encoded)
			g_byte_array_unref(m0disp->encoded);
		m0disp->encoded = _encode_meta0_array(array);
	}
	g_mutex_unlock(m0disp->lock);

	if (err) {
		GRID_WARN("META0 reload failed : (%d) %s", err->code, err->message);
		g_clear_error(&err);
	}
}

/* -------------------------------------------------------------------------- */

static gboolean
meta0_dispatch_v1_GETONE(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored)
{
	GError *err;
	guint8 prefix[2] = {0,0};
	gchar **urlv = NULL;

	(void) ignored;
	err = extract_prefix(reply->request, "PREFIX", TRUE, prefix);
	if (NULL != err) {
		reply->send_error(400, err);
		return TRUE;
	}

	reply->subject("%02X%02X", prefix[0], prefix[1]);

	err = meta0_backend_get_one(m0disp->m0, prefix, &urlv);
	if (NULL != err) {
		g_prefix_error(&err, "Backend error: ");
		reply->send_error(500, err);
		return TRUE;
	}

	reply->add_body(_encode_meta0_tree(urlv_to_tree(prefix, urlv)));
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta0_dispatch_v1_GETALL(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored)
{
	(void) ignored;
	reply->add_body(_get_encoded(m0disp));
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta0_dispatch_v1_FILL(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored)
{
	GError *err;
	gchar **urls = NULL;
	guint nbreplicas = 1;

	(void) ignored;
	err = message_extract_struint(reply->request, "REPLICAS", &nbreplicas);
	if (err != NULL) {
		reply->send_error(400, err);
		return TRUE;
	}

	err = message_extract_body_strv(reply->request, &urls);
	if (err != NULL) {
		reply->send_error(400, err);
		return TRUE;
	}

	reply->subject("repl=%u|m1=%u", nbreplicas, g_strv_length(urls));

	err = meta0_backend_fill(m0disp->m0, nbreplicas, urls);
	g_strfreev(urls);

	if (!err)
		reply->send_reply(200, "OK");
	else
		reply->send_error(0, err);

	return TRUE;
}

static gboolean
meta0_dispatch_v1_RELOAD(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored)
{
	GError *err;

	(void) ignored;
	if (NULL != (err = meta0_backend_reload(m0disp->m0))) {
		g_prefix_error(&err, "Backend error: ");
		reply->send_error(0, err);
		return TRUE;
	}

	_reload(m0disp);
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta0_dispatch_v2_FILL(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored)
{
	(void) ignored;
	GError *err;
	guint nbreplicas = 1;
	gboolean nodist = FALSE;

	err = message_extract_struint(reply->request, "REPLICAS", &nbreplicas);
	if (err != NULL) {
		reply->send_error(400, err);
		return TRUE;
	}
	err = message_extract_struint(reply->request, "NODIST", (guint*)&nodist);
	if (err != NULL) {
		reply->send_error(400, err);
		return TRUE;
	}

	reply->subject("repl=%u, nodist=%u", nbreplicas, nodist);

	err = meta0_assign_fill(m0disp->m0, m0disp->ns_name, nbreplicas, nodist);
	if (!err)
		reply->send_reply(200, "OK");
	else
		reply->send_error(0, err);

	return TRUE;
}


static gboolean
meta0_dispatch_v2_ASSIGN_PREFIX(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored)
{
	GError *err;

	(void) ignored;
	err = meta0_assign_prefix_to_meta1(m0disp->m0, m0disp->ns_name,
			extract_nocheck(reply->request));
	if (NULL != err) {
		reply->send_error(0, err);
		return TRUE;
	}

	_reload(m0disp);
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta0_dispatch_v2_DISABLE_META1(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored)
{
	GError *err;
	gchar **urls = NULL;

	(void) ignored;

	err = message_extract_body_strv(reply->request, &urls);
	if (err != NULL) {
		reply->send_error(400, err);
		return TRUE;
	}

	reply->subject("m1=%u", g_strv_length(urls));

	err = meta0_assign_disable_meta1(m0disp->m0, m0disp->ns_name, urls,
			extract_nocheck(reply->request));
	if (NULL != err) {
		g_prefix_error(&err, "disable meta1 error:");
		reply->send_error(0, err);
		return TRUE;
	}

	_reload(m0disp);
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta0_dispatch_v2_META1_INFO(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored)
{
	(void) ignored;

	reply->add_body(_encode_meta1ref(m0disp));
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta0_dispatch_v2_DESTROY_META1REF(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored)
{
	GError *err;
	gchar meta1url[STRLEN_ADDRINFO];
	(void) ignored;

	err = message_extract_string(reply->request, "METAURL", meta1url, sizeof(meta1url));
	if (err != NULL) {
		reply->send_error(400, err);
		return TRUE;
	}

	err = meta0_backend_destroy_meta1_ref(m0disp->m0, meta1url);
	if (NULL != err) {
		g_prefix_error(&err, "destroy meta1_ref error:");
		reply->send_error(0, err);
		return TRUE;
	}

	_reload(m0disp);
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
meta0_dispatch_v2_DESTROY_ZKNODE(struct gridd_reply_ctx_s *reply,
		struct meta0_disp_s *m0disp, gpointer ignored)
{
	GError *err;
	gchar meta0url[STRLEN_ADDRINFO];
	(void) ignored;

	err = message_extract_string(reply->request, "METAURL", meta0url, sizeof(meta0url));
	if (err != NULL) {
		reply->send_error(400, err);
		return TRUE;
	}

	if ( NULL != (err = delete_zk_node(m0disp->m0zkmanager,NULL,meta0url))) {
		g_prefix_error(&err, "Failed to destroy meta0 in zookeeper :");
		reply->send_error(0, err);
		return TRUE;
	}

	reply->send_reply(200, "OK");
	return TRUE;
}


/* ------------------------------------------------------------------------- */

typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);

const struct gridd_request_descr_s *
meta0_gridd_get_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {
		{"REQ_M0_GETONE",  (hook) meta0_dispatch_v1_GETONE,  NULL},
		{"REQ_M0_GETALL",  (hook) meta0_dispatch_v1_GETALL,  NULL},
		{"REQ_M0_FILL",    (hook) meta0_dispatch_v1_FILL,    NULL},
		{"REQ_M0_RELOAD",  (hook) meta0_dispatch_v1_RELOAD,  NULL},
		{"REQ_M0_V2_ASSIGN_PREFIX", (hook)meta0_dispatch_v2_ASSIGN_PREFIX, NULL},
		{"REQ_M0_V2_DISABLE_META1", (hook)meta0_dispatch_v2_DISABLE_META1, NULL},
		{"REQ_M0_V2_FILL",   (hook) meta0_dispatch_v2_FILL, NULL},
		{"REQ_M0_V2_GETMETA1INFO", (hook)meta0_dispatch_v2_META1_INFO, NULL},
		{"REQ_M0_V2_DESTROY_META1REF", (hook)meta0_dispatch_v2_DESTROY_META1REF, NULL},
		{"REQ_M0_V2_DESTROY_META0ZKNODE", (hook)meta0_dispatch_v2_DESTROY_ZKNODE, NULL},
		{NULL, NULL, NULL}
	};

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	return descriptions;
}

void
meta0_gridd_requested_reload(struct meta0_disp_s *m0disp)
{
	m0disp->reload_requested = TRUE;
	meta0_backend_reload_requested(m0disp->m0);
}

struct meta0_disp_s*
meta0_gridd_get_dispatcher(struct meta0_backend_s *m0,
		struct zk_manager_s *m0zkmanager, gchar* ns_name)
{
	struct meta0_disp_s *result;

	result = g_malloc0(sizeof(*result));
	result->ns_name = g_strdup(ns_name);
	result->m0 = m0;
	result->m0zkmanager = m0zkmanager;
	result->lock = g_mutex_new();

	meta0_gridd_requested_reload(result);
	return result;
}

void
meta0_gridd_free_dispatcher(struct meta0_disp_s *m0disp)
{
	if (!m0disp)
		return;
	if (m0disp->lock)
		g_mutex_free(m0disp->lock);
	if (m0disp->encoded)
		g_byte_array_unref(m0disp->encoded);
	memset(m0disp, 0, sizeof(*m0disp));
	g_free(m0disp);
}

