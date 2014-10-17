#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gs-rawx-list"
#endif
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <rawx-lib/src/rawx.h>

#include "../lib/chunk_db.h"

static gboolean flag_contents = FALSE;
static gboolean flag_containers = FALSE;
static gchar path_volume[1024] = "";

/* -------------------------------------------------------------------------- */

static gboolean
cb_print(gchar *tag, GByteArray *k, GByteArray *v)
{
	gchar *str_k, *str_v, *result, *array[4];
	int i=0;

	str_k = g_strndup((gchar*)k->data, k->len);
	str_v = g_strndup((gchar*)v->data, v->len);
	if (tag)
		array[i++] = tag;
	array[i++] = str_k ? str_k : "NULL";
	array[i++] = str_v ? str_v : "NULL";
	array[i++] = NULL;
	result = g_strjoinv("|", array);

	g_print(result);
	g_print("\n");

	g_free(result);
	g_free(str_k);
	g_free(str_v);
	return TRUE;
}

static gboolean
cb_container(GByteArray *k, GByteArray *v)
{
	return cb_print("container", k, v);
}

static gboolean
cb_content(GByteArray *k, GByteArray *v)
{
	return cb_print("content", k, v);
}

static gboolean
cb_none(GByteArray *k, GByteArray *v)
{
	return cb_print(NULL, k, v);
}

/* ------------------------------------------------------------------------- */

static void
main_action(void)
{
	GError *local_error;

	if (!(flag_contents ^ flag_containers)) {
		local_error = NULL;
		if (!list_container_chunks(path_volume, &local_error, cb_container))
			GRID_ERROR("Failed to list the {content,chunk} pairs of [%s] : %s",
					path_volume, gerror_get_message(local_error));
		if (local_error)
			g_clear_error(&local_error);

		local_error = NULL;
		if (!list_content_chunks(path_volume, &local_error, cb_content))
			GRID_ERROR("Failed to list the {content,chunk} pairs of [%s] : %s",
					path_volume, gerror_get_message(local_error));
		if (local_error)
			g_clear_error(&local_error);
	}

	if (flag_containers) {
		local_error = NULL;
		if (!list_container_chunks(path_volume, &local_error, cb_none))
			GRID_ERROR("Failed to list the {content,chunk} pairs of [%s] : %s",
					path_volume, gerror_get_message(local_error));
		if (local_error)
			g_clear_error(&local_error);
	}

 	if (flag_contents) {
		local_error = NULL;
		if (!list_content_chunks(path_volume, &local_error, cb_none))
			GRID_ERROR("Failed to list the {content,chunk} pairs of [%s] : %s",
					path_volume, gerror_get_message(local_error));
		if (local_error)
			g_clear_error(&local_error);
	}
}

static void
main_set_defaults(void)
{
	bzero(path_volume, sizeof(path_volume));
}

static gboolean
main_configure(int argc, char **args)
{
	if (!argc) {
		GRID_ERROR("Missing arguments");
		return FALSE;
	}

	/* Save the volume's name and introspects the volumes XATTR for
	 * a namespaces name and a RAWX url */
	if (sizeof(path_volume) <= g_strlcpy(path_volume, args[0], sizeof(path_volume)-1)) {
		GRID_ERROR("Volume path name too long");
		return FALSE;
	}

	if (!(flag_contents ^ flag_contents))
		GRID_DEBUG("Listing the contents and containers of %s", path_volume);
	if (flag_contents)
		GRID_DEBUG("Listing the contents of %s", path_volume);
	if (flag_containers)
		GRID_DEBUG("Listing the containers of %s", path_volume);

	return TRUE;
}

static void
main_specific_stop(void)
{
}

static void
main_specific_fini(void)
{
}

static struct grid_main_option_s*
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{"DisplayContainers", OT_BOOL, {.b=&flag_containers}, "Display containers"},
		{"DisplayContents", OT_BOOL, {.b=&flag_contents}, "Display contents"},
		{NULL, 0, {.b=0}, NULL}
	};

	return options;
}

static const gchar*
main_get_usage(void)
{
	static gchar xtra_usage[] =
		"\tExpected argument: an absolute path a a valid RAWX volume\n"
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

