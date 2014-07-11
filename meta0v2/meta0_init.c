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

static gint nbreplicas = 1;
static gchar **urls;
static addr_info_t addr;
static gchar *namespace=NULL;
static gboolean flag_fill_v1 =FALSE;
static gboolean nodist = FALSE;


static gboolean
url_check(const gchar *url)
{
	addr_info_t a;
	return grid_string_to_addrinfo(url, NULL, &a);
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
_getMeta0addr(GSList **m0_lst, GSList *exclude ) {
	if ( namespace ) {
		return  meta0_utils_getMeta0addr(namespace,m0_lst,exclude);
	} else {
		if ( !exclude )
			return &addr;
	}
	return NULL;
}


static void
meta0_action(void)
{
	GError *err = NULL;
	gboolean result = FALSE;
	GSList *m0_lst = NULL;
	GSList *exclude = NULL;
	addr_info_t *m0addr;

	m0addr = _getMeta0addr(&m0_lst,exclude);
	while (m0addr) {
		if ( flag_fill_v1 )
			result=meta0_remote_fill(m0addr, 60000, urls, nbreplicas, &err);
		else
			result=meta0_remote_fill_v2(m0addr, 60000, nbreplicas, nodist, &err);

		if (!result) {
			if ( err->code < 300 ) {
				exclude=g_slist_prepend(exclude,m0addr);
				m0addr = _getMeta0addr(&m0_lst,exclude);
			} else {
				GRID_WARN("META0 request error (%d) : %s",
					err->code, err->message);
				g_clear_error(&err);
				m0addr=NULL;
			}
		} else {
			GRID_INFO("META0 filled!");
			break;
		}	
	}
}

static const char *
meta0_usage(void)
{
	return "META0_URL [META1_URL...]";
}

static struct grid_main_option_s *
meta0_get_options(void)
{
	static struct grid_main_option_s meta0_options[] = {
		{"NbReplicas", OT_INT, {.i=&nbreplicas},
			"Specificy a number of replicas (strictly greater than 0)"},
		{"IgnoreDistance", OT_BOOL, {.b=&nodist},
			"Allow replication on meta1 services with the same IP"},
		{NULL, 0, {.i=0}, NULL}
	};
	return meta0_options;
}

static void
meta0_specific_fini(void)
{
	if (urls) {
		g_strfreev(urls);
		urls = NULL;
	}
}

static void
meta0_set_defaults(void)
{
	urls = NULL;
	memset(&addr, 0, sizeof(addr));
}

static gboolean
meta0_configure(int argc, char **argv)
{
	if (argc < 1 ) {
		GRID_WARN("Not enough options, see usage.");
		return FALSE;
	}

	if (nbreplicas < 1 || nbreplicas > 1024) {
		GRID_WARN("Invalid number of replicas");
		return FALSE;
	}

	if (!grid_string_to_addrinfo(argv[0], NULL, &addr)) {
		namespace = strdup(argv[0]);
	}

	if ( argc >= 2 ) {
		// meta1 addr 
		if (!urlv_check(argv+1)) {
			GRID_WARN("Invalid META1 address");
			return FALSE;
		}

		urls = g_strdupv(argv+1);
		flag_fill_v1 = TRUE;
		GRID_INFO("Ready to configure [%u] META1", g_strv_length(urls));
	}
	return TRUE;
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

