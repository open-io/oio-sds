#include "metautils.h"

static void
main_specific_stop(void)
{
}

static const gchar*
main_get_usage(void)
{
	return "";
}

static void
main_set_defaults(void)
{
}

static struct grid_main_option_s *
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{ NULL, 0, {.b=NULL}, NULL }
	};

	return options;
}

static gboolean
main_configure(int argc, char **args)
{
	(void) argc;
	(void) args;
	return TRUE;
}

static void
main_specific_fini(void)
{
}

static void
test_round(void)
{
	TRACE2("TRACE2\tno domain");
	TRACE_DOMAIN("dom0", "TRACE\ttab");
	DEBUG_DOMAIN("dom0.debug", "DEBUG\ttab");
	INFO_DOMAIN("domain1.info", "INFO\ttab");
	NOTICE_DOMAIN(G_LOG_DOMAIN, "NOTICE\ttab default domain");
	WARN_DOMAIN("dom0", "WARN\ttab");
	ERROR_DOMAIN("dom0.0", "ERROR\ttab");
}

static void
main_action(void)
{
	g_printerr("\n*** Default flags enabled\n");
	test_round();

	g_printerr("\n*** All flags enabled\n");
	main_log_flags = ~0;
	test_round();

	g_printerr("\n*** TRIM_DOMAIN disabled\n");
	main_log_flags &= ~LOG_FLAG_TRIM_DOMAIN;
	test_round();

	g_printerr("\n*** PURIFY disabled\n");
	main_log_flags &= ~LOG_FLAG_PURIFY;
	test_round();

	g_printerr("\n*** COLUMNIZE disabled\n");
	main_log_flags &= ~LOG_FLAG_COLUMNIZE;
	test_round();
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
	return grid_main(argc, argv, &cb);
}

