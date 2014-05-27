#ifndef  G_LOG_DOMAIN
# define G_LOG_DOMAIN "m1v2.test.list"
#endif

#include <metautils/lib/metautils.h>

#include "./meta1_remote.h"

static gchar m1url[STRLEN_ADDRINFO];
static addr_info_t m1addr;
static gchar nsname[LIMIT_LENGTH_NSNAME];
static gchar prefix_hex[STRLEN_CONTAINERID];
static container_id_t prefix;
static gchar srvtype[LIMIT_LENGTH_SRVTYPE];
static gchar srvurl[STRLEN_ADDRINFO];

static struct grid_main_option_s *
main_option(void)
{
	static struct grid_main_option_s options[] = {
		{NULL,0,{.b=NULL},NULL}
	};
	return options;
}

static void
main_action(void)
{
	GError *err;
	GByteArray *result = NULL;

	if (*srvurl && *srvtype) {
		GRID_INFO("Listing the references on M1V2 [%s] for NS [%s], prefix [%s], srvtype [%s] and srvurl [%s]",
				m1url, nsname, prefix_hex, srvtype, srvurl);
		err = meta1v2_remote_list_references_by_service(&m1addr, nsname, prefix, srvtype, srvurl, &result);
	}
	else {
		GRID_INFO("Listing the references on M1V2 [%s] for NS [%s] and prefix [%s]",
				m1url, nsname, prefix_hex);
		err = meta1v2_remote_list_references(&m1addr, nsname, prefix, &result);
	}

	if (err) {
		GRID_WARN("M1V2 error : (%d) %s", err->code, err->message);
		metautils_gba_unref(result);
		g_clear_error(&err);
		exit(1);
	}

	g_print("# Buffer size=%u\n", result->len);
	g_byte_array_append(result, (guint8*)"", 1);
	g_print("%s\n", (gchar*)result->data);
	metautils_gba_unref(result);
}

static void
main_set_defaults(void)
{
	ZERO(m1url);
	memset(&m1addr, 0, sizeof(m1addr));
	ZERO(nsname);
	ZERO(prefix_hex);
	memset(prefix, 0, sizeof(container_id_t));
	ZERO(srvtype);
	ZERO(srvurl);
}

static void
main_specific_fini(void)
{
}

static gboolean
main_configure(int argc, char **argv)
{
	GError *err = NULL;

	if (argc != 3 && argc != 5) {
		GRID_WARN("Invalid arguments number");
		return FALSE;
	}

	g_strlcpy(m1url, argv[0], sizeof(m1url));
	if (!l4_address_init_with_url(&m1addr, argv[0], &err)) {
		GRID_WARN("Invalid M1 URL[%s] : %s", argv[0], err->message);
		g_clear_error(&err);
		return FALSE;
	}

	if (sizeof(nsname) <= g_strlcpy(nsname, argv[1], sizeof(nsname))) {
		GRID_WARN("NS name[%s] truncated to [%s]", argv[1], nsname);
		return FALSE;
	}

	g_strlcpy(prefix_hex, argv[2], sizeof(prefix_hex));
	if (!hex2bin(argv[2], prefix, MIN(strlen(prefix_hex)/2,sizeof(container_id_t)), &err)) {
		GRID_WARN("Invalid hex prefix [%s] : %s", argv[2], err->message);
		g_clear_error(&err);
		return FALSE;
	}

	if (argc == 5) {
		if (sizeof(srvtype) <= g_strlcpy(srvtype, argv[3], sizeof(srvtype))) {
			GRID_WARN("SRV type [%s] truncated to [%s]", argv[3], srvtype);
			return FALSE;
		}

		if (sizeof(srvurl) <= g_strlcpy(srvurl, argv[4], sizeof(srvurl))) {
			GRID_WARN("SRV url [%s] truncated to [%s]", argv[4], srvurl);
			return FALSE;
		}
	}

	return TRUE;
}

static const char *
main_usage(void)
{
	return "M1URL NS PREFIX [SRVTYPE SRVURL]";
}

static void
main_specific_stop(void)
{
}

static struct grid_main_callbacks main_callbacks = {
	.options = main_option,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_usage,
	.specific_stop = main_specific_stop
};

int
main(int argc, char **argv)
{
	return grid_main_cli(argc, argv, &main_callbacks);
}

