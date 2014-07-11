#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.tools"
#endif

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/events/gridcluster_events.h>
#include <cluster/events/gridcluster_eventsremote.h>
#include <cluster/events/gridcluster_eventhandler.h>
#include <cluster/lib/gridcluster.h>

static gboolean flag_fancy = FALSE;

static GSList *list_paths = NULL; 

/* ------------------------------------------------------------------------- */

static gridcluster_event_t*
event_load(const gchar *path)
{
	gboolean rc;
	gchar *ueid = NULL;
	gridcluster_event_t *event = NULL;
	gchar *encoded = NULL;
	gsize encoded_size = 0;
	GError *local_error = NULL;

	ueid = g_path_get_basename(path);

	rc = g_file_get_contents(path, &encoded, &encoded_size, &local_error);
	if (!rc || !encoded || !encoded_size) {
		GRID_ERROR("UEID[%s] g_file_get_contents(%s) rc=%d encoded=%p %"G_GSIZE_FORMAT" bytes : %s",
			ueid, path, rc, encoded, encoded_size, gerror_get_message(local_error));
		goto label_free_ueid;
	}
	else {
		GRID_DEBUG("UEID[%s] g_file_get_contents(%s) rc=%d encoded=%p %"G_GSIZE_FORMAT" bytes",
			ueid, path, rc, encoded, encoded_size);
	}

	event = gridcluster_decode_event2((guint8*)encoded, encoded_size, &local_error);
	if (!event) {
		GRID_ERROR("UEID[%s] gridcluster_decode_event2(...) : %s",
				ueid, gerror_get_message(local_error));
	}

	g_free(encoded);

label_free_ueid:
	g_free(ueid);
	if (local_error)
		g_clear_error(&local_error);
	return event;
}

static gboolean
gba_is_printable(GByteArray *gba)
{
	gsize i;

	g_assert(gba != NULL);
	g_assert(!gba->len || gba->data != NULL);

	for (i=0; i<gba->len ;i++) {
		gchar c = (gchar) gba->data[i];
		if (c && !g_ascii_isspace(c) && !g_ascii_isprint(c))
			return FALSE;
	}
	return TRUE;
}

static void
event_dump(const gchar *path, gridcluster_event_t *event)
{
	GList *list_keys, *l;

	(void) path;

	list_keys = g_hash_table_get_keys(event);
	list_keys = g_list_sort(list_keys, (GCompareFunc)g_ascii_strcasecmp);
	for (l=list_keys; l ;l=l->next) {
		gsize i;
		gchar *k;
		GByteArray *value;
		gboolean is_printable;

		k = l->data;
		value = g_hash_table_lookup(event, k);
		is_printable = gba_is_printable(value);

		/* Header */
		if (flag_fancy)
			g_print("[%s] : size=%u\n\t[", k, value->len);
		else if (path)
			g_print("%s:%s:%u:", path, k, value->len);
		else
			g_print("%s:%u:", k, value->len);

		/* Body */
		if (is_printable) {
			for (i=0; i<value->len ;i++) {
				gchar c = (gchar) value->data[i];
				switch (c) {
					case '\0': g_print("\\0"); break;
					case '\t': g_print("\\t"); break;
					case '\n': g_print("\\n"); break;
					case '\r': g_print("\\r"); break;
					default: g_print("%c", c); break;
				}
			}
		}
		else {
			g_print("0x");
			for (i=0; i<value->len ;i++)
				g_print("%02X", value->data[i]);
		}

		/* End of Value */
		if (flag_fancy)
			g_print("]\n");
		else
			g_print("\n");
	}
	g_list_free(list_keys);
}

static void
main_action(void)
{
	gridcluster_event_t *event;
	guint list_length;
	GSList *l;

	list_length = g_slist_length(list_paths);

	for (l=list_paths; l ;l=l->next) {
		gchar *path = l->data;

		g_print("# file: %s\n", path);
		if (NULL != (event = event_load(path))) {
			event_dump(list_length>1 ? path : NULL, event);
			g_hash_table_destroy(event);
		}
		else
			g_print("error\n");
	}
}

static gboolean
main_configure(int argc, char **args)
{
	int i;

	for (i=0; i<argc ;i++)
		list_paths = g_slist_prepend(list_paths, g_strdup(args[i]));

	return TRUE;
}

static void
main_specific_fini(void)
{
	if (list_paths) {
		g_slist_foreach(list_paths, g_free1, NULL);
		g_slist_free(list_paths);
	}
}

static struct grid_main_option_s*
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{"FormatFancy", OT_BOOL, {.b=&flag_fancy},
			"Pretty printing"},
		{NULL, 0, {.b=0}, NULL}
	};

	return options;
}

static void
main_set_defaults(void)
{
	flag_fancy = FALSE;
	list_paths = NULL;
}

static const gchar*
main_get_usage(void)
{
	static gchar xtra_usage[] = "\tPATH...\n" ;
	return xtra_usage;
}

static void
main_specific_stop(void)
{
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

