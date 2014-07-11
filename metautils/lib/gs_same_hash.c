
#include <string.h>

#include "./metautils.h"
#include "./resolv.h"
#include "./common_main.h"

#define COUNT 65536

static gchar* memory[65536];
static GString *prefix;

static struct grid_main_option_s *
main_option(void)
{
	static struct grid_main_option_s options[] = {
		{"Prefix",OT_STRING,{.str=&prefix},
			"Explicit prefix to the reference name"},
		{NULL,0,{.b=NULL},NULL}
	};
	return options;
}

static void
main_action(void)
{
	gint64 counter;
	GChecksum *c;
	gchar num[64];
	union {
		guint8 b[32];
		guint16 prefix;
	} bin;
	gsize binsize;

	memset(&bin, 0, sizeof(bin));
	counter = 0;
	c = g_checksum_new(G_CHECKSUM_SHA256);

	if (prefix && prefix->len > 0) {
		/* pre-loads the memory with the prefix only */
		g_checksum_update(c, (guint8*) prefix->str, prefix->len);
		binsize = sizeof(bin.b);
		g_checksum_get_digest(c, bin.b, &binsize);
		memory[bin.prefix] = g_strdup(prefix->str);
	}

	while (grid_main_is_running()) {

		GString *gstr = g_string_new("");
		if (prefix && prefix->len > 0)
			g_string_append_len(gstr, prefix->str, prefix->len);
		g_snprintf(num, sizeof(num), "%"G_GINT64_FORMAT, counter++);
		g_string_append(gstr, num);

		g_checksum_reset(c);
		g_checksum_update(c, (guint8*) gstr->str, gstr->len);
		binsize = sizeof(bin.b);
		g_checksum_get_digest(c, bin.b, &binsize);

		if (memory[bin.prefix]) {
			g_print("%02X%02X %s %s\n", bin.b[0], bin.b[1],
					memory[bin.prefix], gstr->str);
			g_free(memory[bin.prefix]);
		}

		memory[bin.prefix] = g_string_free(gstr, FALSE);
	}

	g_checksum_free(c);
}

static void
main_set_defaults(void)
{
	prefix = NULL;
	memset(memory, 0, sizeof(memory));
}

static void
main_specific_fini(void)
{
	guint i;
	for (i=0; i < COUNT ;i++) {
		if (memory[i])
			g_free(memory[i]);
	}
}

static gboolean
main_configure(int argc, char **argv)
{
	(void) argc;
	(void) argv;
	return TRUE;
}

static const char *
main_usage(void)
{
	return "";
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

