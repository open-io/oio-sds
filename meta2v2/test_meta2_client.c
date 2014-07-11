#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m2v2.test.client"
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>

#include <meta2/remote/meta2_remote.h>
#include <meta2/remote/meta2_services_remote.h>

static struct hc_url_s *url = NULL;
static struct addr_info_s addr;
static time_t timeout = 60000;

static void
CHECK_RC_ERR(int rc, GError *err, const gchar *action)
{
	if (!rc) {
		g_assert(err != NULL);
		g_error("%s error : %d %s", action, err->code, err->message);
		g_assert_not_reached();
	}
	else {
		if (err)
			g_error("%s UNEXPECTED error : %d %s", action, err->code, err->message);
		g_assert(err == NULL);
	}
}

static const gchar*
next_name(const gchar *tag)
{
	static gchar path[1024];
	static gint counter = 0;

	GTimeVal tv;
	g_get_current_time(&tv);

	g_snprintf(path, sizeof(path), "%s-%d-%ld-%ld-%d", tag,
			getpid(), tv.tv_sec, tv.tv_usec, ++counter);
	return path;
}

static meta2_raw_content_v2_t*
generate_v2(void)
{
	meta2_raw_content_v2_t *v2 = g_malloc0(sizeof(*v2));
	memcpy(v2->header.container_id, hc_url_get_id(url), sizeof(container_id_t));
	g_strlcpy(v2->header.path, hc_url_get(url, HCURL_PATH), sizeof(v2->header.path));
	v2->header.nb_chunks = 1;
	v2->header.size = 0;
	v2->header.metadata = g_byte_array_new();
	v2->header.system_metadata = g_byte_array_new();

	meta2_raw_chunk_t *rc = g_malloc0(sizeof(*rc));
	l4_address_init_with_url(&(rc->id.addr), "127.0.0.1:6000", NULL);
	g_strlcpy(rc->id.vol, "/rawx-1", sizeof(rc->id.vol));
	rc->metadata = g_byte_array_new();
	v2->raw_chunks = g_slist_prepend(v2->raw_chunks, rc);

	return v2;
}

static void
wrapper(void (*cb)(void))
{
	gboolean rc = FALSE;
	GError *err = NULL;

	g_printerr("\n");
	hc_url_set(url, HCURL_REFERENCE, next_name("container"));
	hc_url_set(url, HCURL_PATH, next_name("content"));
	g_debug("ROUND with [%s] %s", hc_url_get(url, HCURL_HEXID),
			hc_url_get(url, HCURL_WHOLE));

	rc = meta2_remote_container_create(&addr, timeout, &err, hc_url_get_id(url),
			hc_url_get(url, HCURL_REFERENCE));
	CHECK_RC_ERR(rc, err, "CREATE");

	if (cb)
		cb();
}

static void
test_list_empty(void)
{
	void round(void) {
		GError *err = NULL;
		GSList *l;

		l = meta2_remote_container_list(&addr, timeout, &err, hc_url_get_id(url));
		if (!l) {
			if (err) {
				g_error("LIST error : %d %s", err->code, err->message);
				g_assert_not_reached();
			}
		}
		g_debug("LIST : %u elements", g_slist_length(l));
		if (l) {
			g_slist_foreach(l, chunk_info_gclean, NULL);
			g_slist_free(l);
		}
	}
	void cb(void) {
		round();
		round();
		round();
	}
	wrapper(cb);
}

static void
test_open_close(void)
{
	void cb(void) {
		gboolean rc;
		GError *err = NULL;

		rc = meta2_remote_container_open(&addr, timeout, &err, hc_url_get_id(url));
		CHECK_RC_ERR(rc, err, "OPEN");

		rc = meta2_remote_container_open(&addr, timeout, &err, hc_url_get_id(url));
		CHECK_RC_ERR(rc, err, "OPEN");

		rc = meta2_remote_container_open(&addr, timeout, &err, hc_url_get_id(url));
		CHECK_RC_ERR(rc, err, "OPEN");

		rc = meta2_remote_container_close(&addr, timeout, &err, hc_url_get_id(url));
		CHECK_RC_ERR(rc, err, "CLOSE");

		rc = meta2_remote_container_close(&addr, timeout, &err, hc_url_get_id(url));
		CHECK_RC_ERR(rc, err, "CLOSE");

		rc = meta2_remote_container_close(&addr, timeout, &err, hc_url_get_id(url));
		CHECK_RC_ERR(rc, err, "CLOSE");
	}
	wrapper(cb);
}

static gboolean
getall_admin(GError **err)
{
	GHashTable *ht;
	GHashTableIter iter;
	gpointer k, v;
	struct metacnx_ctx_s cnx;

	/* GETALL */
	metacnx_clear(&cnx);
	metacnx_init_with_addr(&cnx, &addr, NULL);
	cnx.timeout.req = cnx.timeout.cnx = timeout;
	ht = meta2raw_remote_get_admin_entries(&cnx, err, hc_url_get_id(url));
	metacnx_close(&cnx);
	metacnx_clear(&cnx);

	if (!ht)
		return FALSE;
	g_hash_table_iter_init(&iter, ht);
	while (g_hash_table_iter_next(&iter, &k, &v))
		g_debug("KV: [%s] = [%s]", (gchar*)k, (gchar*)v);
	g_hash_table_destroy(ht);
	return TRUE;
}

static gboolean
get_property(const gchar *name, GError **err)
{
	gboolean rc;
	struct metacnx_ctx_s cnx;
	gchar *result = NULL;

	/* GETONE */
	metacnx_clear(&cnx);
	metacnx_init_with_addr(&cnx, &addr, NULL);
	cnx.timeout.req = cnx.timeout.cnx = timeout;
	rc = meta2_remote_get_container_property(&cnx, hc_url_get_id(url),
			name, &result, err);
	metacnx_close(&cnx);
	metacnx_clear(&cnx);

	if (rc) {
		g_assert(result != NULL);
		g_free(result);
		result = NULL;
	}
	return rc;
}

static gboolean
get_properties(GError **err)
{
	gboolean rc;
	GSList *result = NULL;
	struct metacnx_ctx_s cnx;

	metacnx_clear(&cnx);
	metacnx_init_with_addr(&cnx, &addr, NULL);
	cnx.timeout.req = cnx.timeout.cnx = timeout;
	rc = meta2_remote_list_container_properties(&cnx,
			hc_url_get_id(url), &result, err);
	metacnx_close(&cnx);
	metacnx_clear(&cnx);

	if (!rc) {
		g_assert(result != NULL);
		return FALSE;
	}

	GSList *l;
	for (l=result; l ;l=l->next) {
		struct meta2_property_s *p = l->data;
		g_debug("PROP k[%s] v[%.*s]", p->name,
				(int) p->value->len, (gchar*)p->value->data);
	}
	g_slist_foreach(result, meta2_property_gclean, NULL);
	g_slist_free(result);
	result = NULL;
	return TRUE;
}

static gboolean
get_all_properties(GError **err)
{
	gboolean rc;
	GSList *result = NULL;
	struct metacnx_ctx_s cnx;

	metacnx_clear(&cnx);
	metacnx_init_with_addr(&cnx, &addr, NULL);
	cnx.timeout.req = cnx.timeout.cnx = timeout;
	rc = meta2_remote_list_all_container_properties(&cnx,
			hc_url_get_id(url), &result, err);
	metacnx_close(&cnx);
	metacnx_clear(&cnx);

	if (!rc) {
		g_assert(result != NULL);
		return FALSE;
	}

	GSList *l;
	for (l=result; l ;l=l->next)
		g_debug("L = [%s]", (gchar*) l->data);
	g_slist_foreach(result, g_free1, NULL);
	g_slist_free(result);
	result = NULL;
	return TRUE;
}

static void
test_properties(void)
{
	void round_get(void) {
		GError *err = NULL;
		gboolean rc;

		rc = getall_admin(&err);
		CHECK_RC_ERR(rc, err, "GETALLADMIN");

		rc = get_property("sys.namespace", &err);
		CHECK_RC_ERR(rc, err, "GET_CONTAINER_PROPERTY");

		rc = get_properties(&err);
		CHECK_RC_ERR(rc, err, "LIST_PROPERTIES");

		rc = get_all_properties(&err);
		CHECK_RC_ERR(rc, err, "LIST_ALL_PROPERTIES");
	}
	void cb(void) {
		struct metacnx_ctx_s cnx;
		GError *err = NULL;
		gboolean rc;

		metacnx_clear(&cnx);
		metacnx_init_with_addr(&cnx, &addr, NULL);
		cnx.timeout.cnx = cnx.timeout.req = timeout;

		round_get();

		rc = meta2raw_remote_set_admin_entry(&cnx, &err,
				hc_url_get_id(url), "user.plop",
				"plop_value0", sizeof("plop_value0")-1);
		CHECK_RC_ERR(rc, err, "RAWSETADMIN");

		round_get();

		rc = meta2_remote_replicate_set_container_property(&cnx,
				hc_url_get_id(url), "user.plop", "plop_value", &err);
		CHECK_RC_ERR(rc, err, "SETONEADMIN");

		round_get();

		rc = meta2_remote_replicate_remove_container_property(&cnx,
				hc_url_get_id(url), "user.plop", &err);
		CHECK_RC_ERR(rc, err, "REMOVE");

		round_get();

		rc = meta2_remote_set_container_property(&cnx,
				hc_url_get_id(url), "user.plop", "plop_value", &err);
		CHECK_RC_ERR(rc, err, "SETONEADMIN");

		round_get();

		rc = meta2_remote_remove_container_property(&cnx,
				hc_url_get_id(url), "user.plop", &err);
		CHECK_RC_ERR(rc, err, "REMOVE");

		rc = meta2_remote_set_container_global_property(&cnx,
			hc_url_get_id(url), "user.plop", "plop_value", &err);
		CHECK_RC_ERR(rc, err, "SET_GLOBAL");

		round_get();

		metacnx_close(&cnx);
		metacnx_clear(&cnx);
	}
	wrapper(cb);
}

static void
test_flags(void)
{
	void round(void) {
		gboolean rc;
		guint32 f0=0, f1=0;
		GError *err = NULL;

		/* force the flag to ENABLED */
		rc = meta2_remote_container_get_flag(&addr, timeout, &err,
				hc_url_get_id(url), &f0);
		CHECK_RC_ERR(rc, err, "GETFLAGS-0");

		rc = meta2_remote_container_set_flag(&addr, timeout, &err,
				hc_url_get_id(url), f0);
		CHECK_RC_ERR(rc, err, "SETFLAGS");

		rc = meta2_remote_container_get_flag(&addr, timeout, &err,
				hc_url_get_id(url), &f1);
		CHECK_RC_ERR(rc, err, "GETFLAGS-1");

		g_assert(f0 == f1);

		/* force the flag to a bad value */
		f0 = f1 = -1;

		rc = meta2_remote_container_set_flag(&addr, timeout, &err,
				hc_url_get_id(url), f0);
		CHECK_RC_ERR(rc, err, "SETFLAGS");

		rc = meta2_remote_container_get_flag(&addr, timeout, &err,
				hc_url_get_id(url), &f1);
		CHECK_RC_ERR(rc, err, "GETFLAGS-1");

		g_assert(f0 == f1);

		/* reset the flag */
		f0 = f1 = 0;

		rc = meta2_remote_container_set_flag(&addr, timeout, &err,
				hc_url_get_id(url), f0);
		CHECK_RC_ERR(rc, err, "SETFLAGS");

		rc = meta2_remote_container_get_flag(&addr, timeout, &err,
				hc_url_get_id(url), &f1);
		CHECK_RC_ERR(rc, err, "GETFLAGS-1");

		g_assert(f0 == f1);
	}
	void cb(void) {
		round();
		round();
		round();
	}
	wrapper(cb);
}

static void
test_enable_disable_freeze(void)
{
	void round(void) {
		gboolean rc;
		GError *err = NULL;
		struct metacnx_ctx_s cnx;

		metacnx_clear(&cnx);
		cnx.timeout.req = cnx.timeout.cnx = timeout;
		metacnx_init_with_addr(&cnx, &addr, NULL);

		rc = meta2_remote_container_freeze(&cnx, hc_url_get_id(url), &err);
		CHECK_RC_ERR(rc, err, "FREEZE");

		rc = meta2_remote_container_disable_disabled(&cnx, hc_url_get_id(url), &err);
		CHECK_RC_ERR(rc, err, "DISABLE");

		rc = meta2_remote_container_enable(&cnx, hc_url_get_id(url), &err);
		CHECK_RC_ERR(rc, err, "ENABLE");

		metacnx_close(&cnx);
		metacnx_clear(&cnx);
	}
	void cb(void) {
		round();
		round();
		round();
	}
	wrapper(cb);
}

static void
test_services(void)
{
	void cb(void) {
		GSList singleton;
		GError *err = NULL;
		struct metacnx_ctx_s cnx;
		struct service_info_s *si;
		gboolean rc;
		meta2_raw_content_v2_t *v2 = NULL;
		GSList *result = NULL;
		GSList *l;
		gchar straddr[STRLEN_ADDRINFO];

		metacnx_clear(&cnx);
		cnx.timeout.req = cnx.timeout.cnx = timeout;
		metacnx_init_with_addr(&cnx, &addr, NULL);

		singleton.next = NULL;
		singleton.data = (gpointer)hc_url_get(url, HCURL_PATH);

		/* replicate content insertion */
		v2 = generate_v2();
		rc = meta2_remote_replicate_content_v2(&cnx, hc_url_get_id(url), v2, &err);
		CHECK_RC_ERR(rc, err, "REPLICATE");
		meta2_raw_content_v2_clean(v2);

		/* can't touch this! */
		rc = meta2_remote_touch_content(&cnx, hc_url_get_id(url),
				hc_url_get(url, HCURL_PATH), &err);
		CHECK_RC_ERR(rc, err, "TOUCH-CONTENT");

		rc = meta2_remote_touch_container(&cnx, hc_url_get_id(url), &err);
		CHECK_RC_ERR(rc, err, "TOUCH-CONTAINER");

		/* STATv2 */
		v2 = NULL;
		rc = meta2_remote_stat_content_v2(&cnx, hc_url_get_id(url),
				hc_url_get(url, HCURL_PATH), &v2, &err);
		CHECK_RC_ERR(rc, err, "STATV2");
		do {
			gchar *s = meta2_raw_content_v2_to_string(v2);
			g_debug("V2 = %s", s);
			g_free(s);
		} while (0);
		meta2_raw_content_v2_clean(v2);
		v2 = NULL;

		/* properties SET */
		/* properties GET */
		/* properties LIST */

		/* SVC ADD */
		si = meta2_remote_service_add_contents(&cnx, hc_url_get_id(url),
				"tsmx", &singleton, &err);
		if (!si) {
			g_assert(err != NULL);
			g_error("%s error : %d %s", "SVC_ADD", err->code, err->message);
			g_assert_not_reached();
		}
		else {
			gchar *str = service_info_to_string(si);
			g_debug("GOT %s", str);
			g_free(str);
			service_info_clean(si);
		}

		/* SVC SPARE */
		si = meta2_remote_service_add_spares(&cnx, hc_url_get_id(url),
				"tsmx", &singleton, &err);
		if (!si) {
			g_assert(err != NULL);
			g_error("%s error : %d %s", "SVC_ADD", err->code, err->message);
			g_assert_not_reached();
		}
		else {
			gchar *str = service_info_to_string(si);
			g_debug("GOT %s", str);
			g_free(str);
			service_info_clean(si);
		}

		/* useless: SVC COMMIT */
		result = NULL;
		rc = meta2_remote_service_commit_contents(&cnx, hc_url_get_id(url),
				"tsmx", &singleton, &result, &err);
		if (result) {
			for (l=result; l ;l=l->next)
				g_debug("COMMIT RETURN : [%s]", (gchar*) l->data);
			g_slist_foreach(result, g_free1, NULL);
			g_slist_free(result);
			result = NULL;
		}
		if (!rc) {
			g_assert(err != NULL);
			g_error("%s error : %d %s", "SVC_COMMIT", err->code, err->message);
			g_assert_not_reached();
		}

		/* useless: SVC ROLLBACK */
		result = NULL;
		rc = meta2_remote_service_rollback_contents(&cnx, hc_url_get_id(url),
				"tsmx", &singleton, &result, &err);
		if (result) {
			for (l=result; l ;l=l->next)
				g_debug("ROLLBACK RETURN : [%s]", (gchar*) l->data);
			g_slist_foreach(result, g_free1, NULL);
			g_slist_free(result);
			result = NULL;
		}
		if (!rc) {
			g_assert(err != NULL);
			g_error("%s error : %d %s", "SVC_ROLLBACK", err->code, err->message);
			g_assert_not_reached();
		}

		/* SVC GET */
		addr_info_t *ai = meta2_remote_service_get_content_service(&cnx,
				hc_url_get_id(url), "tsmx", hc_url_get(url, HCURL_PATH), &err);
		if (ai) {
			g_assert(err == NULL);
			addr_info_to_string(ai, straddr, sizeof(straddr));
			g_debug("SVC got [%s]", straddr);
			addr_info_clean(ai);
			ai = NULL;
		}
		else {
			g_assert(err != NULL);
			g_error("%s error : %d %s", "SVC_GET", err->code, err->message);
			g_assert_not_reached();
		}

		/* SVC LIST */
		result = meta2_remote_service_get_all_used(&cnx, hc_url_get_id(url),
				"tsmx", &err);
		if (result) {
			g_assert(err == NULL);
			for (l=result; l ;l=l->next) {
				addr_info_to_string(l->data, straddr, sizeof(straddr));
				g_debug("SVC listed [%s]", straddr);
			}
			g_slist_foreach(result, addr_info_gclean, NULL);
			g_slist_free(result);
			result = NULL;
		}
		else if (err) {
			g_error("SVC-LIST error : %d %s", err->code, err->message);
			g_assert_not_reached();
		}

		/* SVC DELETE */
		rc = meta2_remote_service_delete_contents(&cnx, hc_url_get_id(url),
				"tsmx", &singleton, NULL, NULL, &err);
		CHECK_RC_ERR(rc, err, "SVC-DELETE");

		/* SVC FLUSH */
		result = NULL;
		rc = meta2_remote_service_flush(&cnx, hc_url_get_id(url), "tsmx",
				&result, &err);
		if (result) {
			for (l=result; l ;l=l->next)
				g_debug("FLUSH RETURN : [%s]", (gchar*) l->data);
			g_slist_foreach(result, g_free1, NULL);
			g_slist_free(result);
			result = NULL;
		}
		if (!rc) {
			g_assert(err != NULL);
			g_error("%s error : %d %s", "SVC_FLUSH", err->code, err->message);
			g_assert_not_reached();
		}

		metacnx_close(&cnx);
		metacnx_clear(&cnx);
	}
	wrapper(cb);
}

static void
test_contents(void)
{
	void cb(void) {
		/* content ADD */
		/* content SPARE */
		/* content CHUNK_COMMIT */
		/* content CONTENT_COMMIT */

		/* content DEL */
		/* content COMMIT */
	}
	wrapper(cb);
}

int
main(int argc, char **argv)
{
	gint rc;

	if (!g_thread_supported())
		g_thread_init(NULL);
	g_set_prgname(argv[0]);

	memset(&addr, 0, sizeof(addr));
	l4_address_init_with_url(&addr, "127.0.0.1:6010", NULL);
	url = hc_url_empty();
	hc_url_set(url, HCURL_NS, "NS");
	hc_url_set(url, HCURL_REFERENCE, "JFS");

	g_test_init (&argc, &argv, NULL);
	g_log_set_default_handler(logger_stderr, NULL);
	logger_init_level(GRID_LOGLVL_TRACE2);

	g_test_add_func("/meta2/open_close", test_open_close);
	g_test_add_func("/meta2/list_empty", test_list_empty);
	g_test_add_func("/meta2/properties", test_properties);
	g_test_add_func("/meta2/flags", test_flags);
	g_test_add_func("/meta2/freeze_disable_enable", test_enable_disable_freeze);
	g_test_add_func("/meta2/services", test_services);
	g_test_add_func("/meta2/contents", test_contents);

	rc = g_test_run();
	hc_url_clean(url);
	return rc;
}

