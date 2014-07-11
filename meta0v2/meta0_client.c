#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.meta0.client"
#endif

#include <stddef.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "./meta0_remote.h"
#include "./meta0_utils.h"

static addr_info_t addr;
static gchar *namespace;
static gboolean flag_list = FALSE;
static gboolean flag_get = FALSE;
static gboolean flag_reload = FALSE;
static gboolean flag_assign = FALSE;
static gboolean flag_disable_meta1 = FALSE;
static gboolean flag_getmeta1info = FALSE;
static gboolean flag_nocheck = FALSE;
static gboolean flag_destroy_meta1ref = FALSE;
static gboolean flag_destroy_zk_node = FALSE;
static guint8 prefix[2] = {0,0};
static gchar **urls;

static gboolean
url_check(const gchar *u)
{
        addr_info_t a;
        return grid_string_to_addrinfo(u, NULL, &a);
}

static gboolean
urlv_check(gchar **urlv)
{
        gchar **u;

        if (!urlv)
                return FALSE;
        for (u=urlv; *u ;u++) {
                if (!url_check(*u)) {
                        GRID_WARN("Bad address [%s]", *u);
                        return FALSE;
                }
        }
        return TRUE;
}


static addr_info_t *
_getMeta0addr(GSList **m0_lst, GSList *exclude)
{
	if (namespace)
		return  meta0_utils_getMeta0addr(namespace, m0_lst, exclude);
	if (!exclude)
		return &addr;
	return NULL;
}

static void
dump_and_clean_list(GSList *list)
{
	GRID_INFO("(Start of META0 content)");
	if (list) {
		guint i;
		GPtrArray *array;
		gchar **v;

		array = meta0_utils_list_to_array(list);
		meta0_utils_list_clean(list);

		for (i=0; i<array->len ;i++) {
			if (NULL != (v = array->pdata[i])) {
				guint16 p = i;
				gchar *joined = g_strjoinv("|", v);
				g_print("%02X%02X %s\n", ((guint8*)&p)[0],
						((guint8*)&p)[1], joined);
				g_free(joined);
			}
		}

		meta0_utils_array_clean(array);
	}
	GRID_INFO("(End of META0 content)");
}

static void
meta0_init_reload(void)
{
	GError *err = NULL;
	GSList *exclude = NULL;
	GSList *m0_lst = NULL;
	addr_info_t *m0addr;

	GRID_INFO("Refreshing the META0 (internal caches reload)");

	m0addr = _getMeta0addr(&m0_lst, exclude);
	while (m0addr) {
		(void) meta0_remote_cache_refresh(m0addr, 60000, &err);
		gchar url[STRLEN_ADDRINFO];
		addr_info_to_string(m0addr, url , sizeof(url));
		if (err != NULL) {
			GRID_WARN("META0 [%s] refresh error (%d) : %s", url, err->code, err->message);
			g_clear_error(&err);
		} else {
			GRID_WARN("META0 [%s] refresh", url);
		}
		exclude=g_slist_prepend(exclude,m0addr);
		m0addr = _getMeta0addr(&m0_lst,exclude);
	}

	g_slist_free_full(m0_lst, (GDestroyNotify)service_info_clean);
}

static void
meta0_init_list(void)
{
	GError *err = NULL;
	GSList *exclude = NULL;
	GSList *m0_lst = NULL;
	addr_info_t *m0addr;

	GRID_INFO("Dumping the whole META0");

	m0addr = _getMeta0addr(&m0_lst,exclude);
	while (m0addr) {
		GSList *list = meta0_remote_get_meta1_all(m0addr, 60000, &err);
		if (err != NULL) {
			if ( err->code < 300 ) {
				if (DEBUG_ENABLED()) {
					gchar url[STRLEN_ADDRINFO];
					addr_info_to_string(m0addr, url , sizeof(url));
					GRID_DEBUG("Failed to reach meta0 [%s] : error (%d) : %s",
							url, err->code, err->message);
				}
				exclude = g_slist_prepend(exclude,m0addr);
				m0addr = _getMeta0addr(&m0_lst,exclude);
			} else {
				GRID_WARN("META0 request error (%d) : %s", err->code, err->message);
				m0addr = NULL;
			}
			g_clear_error(&err);
		} else {
			dump_and_clean_list(list);
			break;
		}
	}

	g_slist_free_full(m0_lst, (GDestroyNotify)service_info_clean);
}

static void
meta0_init_get(void)
{
	GError *err = NULL;
	GSList *exclude = NULL;
	GSList *m0_lst = NULL;
	addr_info_t *m0addr;

	GRID_INFO("Getting a single META0 entry [%02X%02X]", prefix[0], prefix[1]);

	m0addr = _getMeta0addr(&m0_lst,exclude);
	while (m0addr) {
		GSList *list = meta0_remote_get_meta1_one(m0addr, 60000, prefix, &err);
		if (err != NULL) {
			if ( err->code < 300 ) {
				exclude=g_slist_prepend(exclude,m0addr);
				m0addr = _getMeta0addr(&m0_lst,exclude);
			} else {
				GRID_WARN("META0 request error (%d) : %s", err->code, err->message);
				m0addr=NULL;
			}
			g_clear_error(&err);
		} else {
			dump_and_clean_list(list);
			break;
		}
	}

	g_slist_free_full(m0_lst, (GDestroyNotify)service_info_clean);
}

static void
meta0_init_assign(void)
{
	GError *err = NULL;
	GSList *exclude = NULL;
	GSList *m0_lst = NULL;
	addr_info_t *m0addr;

	GRID_INFO("Assign prefixes to Meta1");

	m0addr = _getMeta0addr(&m0_lst,exclude);
	while (m0addr) {
		(void) meta0_remote_assign(m0addr, 60000, flag_nocheck, &err);
		if (err != NULL) {
			if ( err->code < 300 ) {
				exclude=g_slist_prepend(exclude,m0addr);
				m0addr = _getMeta0addr(&m0_lst,exclude);
			} else {
				GRID_WARN("META0 request error (%d) : %s", err->code, err->message);
				m0addr=NULL;
			}
			g_clear_error(&err);
		} else {
			 GRID_INFO("Assign prefixes terminated!");
			break;
		}
	}

	g_slist_free_full(m0_lst, (GDestroyNotify)service_info_clean);
}

static void
meta0_init_disable_meta1(void)
{
	GError *err = NULL;
	GSList *exclude = NULL;
	GSList *m0_lst = NULL;
	addr_info_t *m0addr;

	GRID_INFO("Disable [%u] META1 services",g_strv_length(urls));

	m0addr = _getMeta0addr(&m0_lst,exclude);
	while (m0addr) {
		(void) meta0_remote_disable_meta1(m0addr, 60000, urls, flag_nocheck, &err);
		if (err != NULL) {
			if ( err->code < 300 ) {
				exclude=g_slist_prepend(exclude,m0addr);
				m0addr = _getMeta0addr(&m0_lst,exclude);
			} else {
				GRID_WARN("META0 request error (%d) : %s", err->code, err->message);
				m0addr=NULL;
			}
			g_clear_error(&err);
		} else {
			GRID_INFO("META1 services disabled!");
			break;
		}
	}

	g_slist_free_full(m0_lst, (GDestroyNotify)service_info_clean);
}

static void
meta0_init_get_meta1_info(void)
{
	GError *err = NULL;
	GSList *exclude = NULL;
	GSList *m0_lst = NULL;
	addr_info_t *m0addr;

	GRID_INFO("GET all META1 information");

	m0addr = _getMeta0addr(&m0_lst,exclude);
	while (m0addr) {
		gchar **result = meta0_remote_get_meta1_info(m0addr, 60000, &err);

		if (err != NULL) {
			if ( err->code < 300 ) {
				exclude = g_slist_prepend(exclude, m0addr);
				m0addr = _getMeta0addr(&m0_lst, exclude);
			} else {
				m0addr=NULL;
			}
			g_clear_error(&err);
		} else {
			if (result != NULL) {
				gchar **u;
				for(u=result; *u ;u++) {
					g_print("%s\n",*u);
				}
				g_strfreev(result);
			} else {
				GRID_INFO("No meta1 referenced");
			}
			break;
		}
	}

	g_slist_free_full(m0_lst, (GDestroyNotify)service_info_clean);
}

static void
meta0_init_destroy_meta1ref(void)
{
	GError *err = NULL;
	GSList *exclude = NULL;
	GSList *m0_lst = NULL;
	addr_info_t *m0addr;

	GRID_INFO("Destroy META1 reference");

	m0addr = _getMeta0addr(&m0_lst,exclude);
	while (m0addr) {
		(void) meta0_remote_destroy_meta1ref(m0addr, 60000, *urls, &err);
		if (err != NULL) {
			if ( err->code < 300 ) {
				exclude=g_slist_prepend(exclude,m0addr);
				m0addr = _getMeta0addr(&m0_lst,exclude);
			} else {
				GRID_WARN("META0 request error (%d) : %s", err->code, err->message);
				m0addr=NULL;
			}
			g_clear_error(&err);
		} else {
			GRID_INFO("META1 reference removed!");
			break;
		}
	}

	g_slist_free_full(m0_lst, (GDestroyNotify)service_info_clean);
}

static void
meta0_init_destroy_zk_node(void)
{
	GError *err = NULL;
	GSList *exclude = NULL;
	GSList *m0_lst = NULL;
	addr_info_t *m0addr;

	GRID_INFO("REMOVE META0 Zookeeper node");

	m0addr = _getMeta0addr(&m0_lst,exclude);
	while (m0addr) {
		(void) meta0_remote_destroy_meta0zknode(m0addr, 60000, *urls, &err);
		if (err != NULL) {
			if ( err->code < 300 ) {
				exclude=g_slist_prepend(exclude,m0addr);
				m0addr = _getMeta0addr(&m0_lst,exclude);
			} else {
				GRID_WARN("META0 request error (%d) : %s", err->code, err->message);
				m0addr=NULL;
			}
			g_clear_error(&err);
		} else {
			GRID_INFO("META0 Zookeeper node removed!");
			break;
		}
	}

}

static void
meta0_action(void)
{
	if (flag_list) {
		meta0_init_list();
	}
	else if (flag_get) {
		meta0_init_get();
	}
	else if (flag_reload) {
		meta0_init_reload();
	}
	else if (flag_assign) {
		meta0_init_assign();
	}
	else if (flag_disable_meta1) {
		meta0_init_disable_meta1();
	}
	else if (flag_getmeta1info) {
		meta0_init_get_meta1_info();
	}
	else if (flag_destroy_meta1ref) {
		meta0_init_destroy_meta1ref();
	}
	else if (flag_destroy_zk_node) {
		meta0_init_destroy_zk_node();
	}
	else {
		GRID_INFO("No action specified");
	}
}

static const char *
meta0_usage(void)
{
	return "Namespace|IP:PORT (get PREFIX|list|reload|get_meta1_info|assign|disable META1_URL...)";
}

static struct grid_main_option_s *
meta0_get_options(void)
{
	static struct grid_main_option_s meta0_options[] = {
		{"NoCheck", OT_BOOL, {.b=&flag_nocheck},
			"Disable checks to relaunch assign"},
		{NULL, 0, {.i=0}, NULL}
	};
	return meta0_options;
}

static void
meta0_specific_fini(void)
{
}

static void
meta0_set_defaults(void)
{
	memset(&addr, 0, sizeof(addr));
}

static gboolean
meta0_configure(int argc, char **argv)
{
	const gchar *command;

	if (argc < 2) {
		GRID_WARN("Not enough options, see usage.");
		return FALSE;
	}

	if (!grid_string_to_addrinfo(argv[0], NULL, &addr)) {
		namespace = strdup(argv[0]);
	}

	command = argv[1];
	if (!g_ascii_strcasecmp(command, "get")) {
		if (argc != 3) {
			GRID_WARN("Missing prefix for the get command, see usage.");
			return FALSE;
		}
		if (!hex2bin(argv[2], prefix, 2, NULL)) {
			GRID_WARN("Invalid prefix for the get command, see usage.");
			return FALSE;
		}
		flag_get = TRUE;
		return TRUE;
	}
	if (!g_ascii_strcasecmp(command, "reload")) {
		if (argc > 2)
			GRID_DEBUG("Exceeding list arguments ignored.");
		flag_reload = TRUE;
		return TRUE;
	}
	if (!g_ascii_strcasecmp(command, "list")) {
		if (argc > 2)
			GRID_DEBUG("Exceeding list arguments ignored.");
		flag_list = TRUE;
		return TRUE;
	}
	if (!g_ascii_strcasecmp(command, "assign")) {
		if (argc > 2)
			GRID_DEBUG("Exceeding list arguments ignored.");
		flag_assign = TRUE;
		return TRUE;
	}
	if (!g_ascii_strcasecmp(command, "disable")) {
		if (argc < 2)
			GRID_DEBUG("Missing META1 addresses .");

		if (!urlv_check(argv+2)) {
			GRID_WARN("Invalid META1 address");
			return FALSE;
		}
		urls = g_strdupv(argv+2);

		flag_disable_meta1 = TRUE;
		return TRUE;
	}
	if (!g_ascii_strcasecmp(command, "get_meta1_info")) {
		if (argc > 2)
			GRID_DEBUG("Exceeding list arguments ignored.");
		flag_getmeta1info = TRUE;
		return TRUE;
	}

	if (!g_ascii_strcasecmp(command, "destroy_meta1ref")) {
		if (argc != 3) {
			GRID_WARN("Missing META1 address");
			return FALSE;
		}
		if (!urlv_check(argv+2)) {
			GRID_WARN("Invalid META1 address");
			return FALSE;
		}
		urls = g_strdupv(argv+2);
		flag_destroy_meta1ref = TRUE;
		return TRUE;
	}

	if (!g_ascii_strcasecmp(command, "destroy_zknode")) {
		if (argc != 3) {
			GRID_WARN("Missing META1 address");
			return FALSE;
		}
		if (!urlv_check(argv+2)) {
			GRID_WARN("Invalid META1 address");
			return FALSE;
		}
		urls = g_strdupv(argv+2);
		flag_destroy_zk_node = TRUE;
		return TRUE;
	}


	GRID_WARN("Invalid command, see usage.");
	return FALSE;
}

static void
meta0_specific_stop(void)
{
	GRID_TRACE("STOP!");
}

static struct grid_main_callbacks meta0_callbacks =
{
	.options = meta0_get_options,
	.action = meta0_action,
	.set_defaults = meta0_set_defaults,
	.specific_fini = meta0_specific_fini,
	.configure = meta0_configure,
	.usage = meta0_usage,
	.specific_stop = meta0_specific_stop,
};

int
main(int argc, char ** argv)
{
	return grid_main(argc, argv, &meta0_callbacks);
}

