#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gs_path2container"
#endif
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

static gboolean flag_auto_enabled = FALSE;

static gint64 auto_bitlength = 17;
static gint64 auto_hoffset = 0;
static gint64 auto_hlength = 0;
static GString *ns_name;

static gboolean flag_read_stdin = FALSE;
static namespace_info_t *ns_info = NULL;
static GSList *list_of_paths = NULL;

/* ------------------------------------------------------------------------- */

static void
hash_path(const gchar *path)
{
	gsize size;
	gsize path_len;
	gchar container_name[LIMIT_LENGTH_CONTAINERNAME+1];

	path_len = strlen(path);

	/* Sanity checks */
	size = auto_hlength;
	if (size <= 0)
		size = path_len - auto_hoffset;

	if ((gsize)auto_hoffset >= path_len) {
		GRID_ERROR("Invalid hash offset (%"G_GINT64_FORMAT"), exceeding the path length (%d)", auto_hoffset, (int)path_len);
		abort();
	}
	if (size > path_len) {
		GRID_ERROR("Invalid hash size (%"G_GINT64_FORMAT"), exceeding the path length (%d)", auto_hlength, (int)path_len);
		abort();
	}
	if (size+auto_hoffset > path_len) {
		GRID_ERROR("Invalid hash offset/size (%"G_GINT64_FORMAT"/%"G_GSIZE_FORMAT"), exceeding the path length (%d)",
				auto_hoffset, size, (int)path_len);
		abort();
	}

	/* Hash itself */
	GRID_DEBUG("Hashing [%s] (len=%"G_GSIZE_FORMAT") (bits=%"G_GSIZE_FORMAT")",
		path+auto_hoffset, size, auto_bitlength);

	metautils_hash_content_path(path+auto_hoffset, size,
		container_name, sizeof(container_name), auto_bitlength);

	g_print("%s %s\n", path, container_name);
}

static void
chomp(gchar *path)
{
	gchar *s;
	register gchar c;

	s = path+(strlen(path)-1);
	for (; s>=path && (c=*s) && (c=='\r' || c=='\n'); s--)
		*s = '\0';
}

static void
hash_path_from_input()
{
	gchar path[LIMIT_LENGTH_CONTENTPATH+1];

	for (;;) {
		int prc;
		struct pollfd pfd;

		bzero(path, sizeof(path));
		if (feof(stdin)) {
			GRID_DEBUG("End of input");
			break;
		}
		if (ferror(stdin)) {
			GRID_ERROR("Input error : %s", strerror(errno));
			break;
		}
		
		pfd.fd = 0;
		pfd.events = POLL_IN;
		pfd.revents = 0;
		prc = poll(&pfd, 1, -1);

		if (!grid_main_is_running())
			break;
		if (prc == 1) {
			if (!fgets(path, sizeof(path), stdin)) {
				GRID_ERROR("Read error : %s", strerror(errno));
				break;
			}

			chomp(path);

			if (!*path)
				continue;

			hash_path(path);
		}
	}
}

/* ------------------------------------------------------------------------- */

static gboolean
main_configure(int argc, char **args)
{
	char **p_arg;
	(void) argc;

	/* Lazy namespace initiation */
	if (ns_name->str[0]) {
		GError *error = NULL;
		if (!(ns_info = get_namespace_info(ns_name->str, &error))) {
			GRID_ERROR("Namespace [%s] cannot be loaded : %s",
				ns_name->str, gerror_get_message(error));
			g_clear_error(&error);
			return FALSE;
		}
	}

	/* Configure the offset/size/bitlength values */
	if (auto_hoffset<=0 && auto_hlength<=0) {
		if (ns_info) {
			/* Get it from the namspace */
			auto_hoffset = namespace_get_autocontainer_src_offset(ns_info);
			auto_hlength = namespace_get_autocontainer_src_size(ns_info);
		}
	}
	if (auto_bitlength <= 0) {
		auto_bitlength = 17;
		if (ns_info) {
			auto_bitlength = namespace_get_autocontainer_dst_bits(ns_info);
		}
	}

	if (auto_hoffset <= 0)
		auto_hoffset = 0;
	if (auto_hlength <= 0)
		auto_hlength = 0;

	if (auto_bitlength <= 0) {
		GRID_ERROR("Invalid hash bitlength [%"G_GINT64_FORMAT"] (negative)", auto_bitlength);
		return FALSE;
	}
	if (auto_bitlength > 256) {
		GRID_ERROR("Invalid hash bitlength [%"G_GINT64_FORMAT"] (too high)", auto_bitlength);
		return FALSE;
	}

	/* Prepare the args for later */
	for (p_arg=args; p_arg && *p_arg ;p_arg++) {
		if (!g_ascii_strcasecmp(*p_arg, "-") || !g_ascii_strcasecmp(*p_arg, "--"))
			flag_read_stdin = TRUE;
		else
			list_of_paths = g_slist_prepend(list_of_paths, *p_arg);
	}

	return TRUE;
}

static void
main_specific_stop(void)
{
}

static void
main_specific_fini(void)
{
	if (ns_info) {
		namespace_info_free(ns_info);
		ns_info = NULL;
	}
	if (list_of_paths) {
		g_slist_free(list_of_paths);
		list_of_paths = NULL;
	}
	if (ns_name) {
		g_string_free(ns_name, TRUE);
		ns_name = NULL;
	}
}

static struct grid_main_option_s*
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{"AutoContainerEnable", OT_BOOL, {.b=&flag_auto_enabled},
			"Perform an automatical hash of the content"},
		{"AutoContainerHashBits", OT_INT64, {.i64=&auto_bitlength},
			"Sets the auto-hash lengh in bits"},
		{"AutoContainerHashOffset", OT_INT64, {.i64=&auto_hoffset},
			"Sets the the offset in the content name used in the auto-hash computation"},
		{"AutoContainerHashSize", OT_INT64, {.i64=&auto_hlength},
			"Sets the the number of bytes in the content name used in the auto-hash computation"},
		{"Namespace", OT_STRING, {.str=&ns_name},
			"Optional namespace, its offset/size/bitlength will be used"},
		{NULL, 0, {.b=0}, NULL}
	};

	return options;
}

static void
main_set_defaults(void)
{
	flag_read_stdin = FALSE;
	list_of_paths = NULL;
	ns_name = g_string_new("");
}

static void
main_action(void)
{
	GSList *l;

	/* Read the paths on the command line */
	list_of_paths = g_slist_reverse(list_of_paths);
	for (l=list_of_paths; l ;l=l->next) {
		if (!l->data)
			continue;
		hash_path(l->data);
	}

	/* Now read stdin if configured */
	if (flag_read_stdin) {
		hash_path_from_input();
	}
}

static const gchar*
main_get_usage(void)
{
	static gchar xtra_usage[] =
		"\tExpected arguments: TOKEN...\n"
		"\twith TOKEN an arbitrary string, or '-' to read other tokens on stdin:\n"
		;
	return xtra_usage;
}

static struct grid_main_callbacks cb =
{
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_get_usage,
	.specific_stop = main_specific_stop
};

int
main(int argc, char **argv)
{
	return grid_main_cli(argc, argv, &cb);
}

