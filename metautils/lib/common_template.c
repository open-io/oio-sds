#include <metautils/lib/metautils.h>
#include <common_main.h>

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
}

static void
main_set_defaults(void)
{
}

static void
main_specific_fini(void)
{
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
	return "place your positional parameters here";
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
	return grid_main_cli(argc, argv, main_callbacks);
}

