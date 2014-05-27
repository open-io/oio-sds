#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.main.config"
#endif

#include <metautils/lib/metautils.h>

#include "config.h"

gboolean
load_config(struct integrity_loop_config_s** config, GError** error)
{
        CHECK_ARG_POINTER(config, error);

	*config = g_try_new0(struct integrity_loop_config_s, 1);
	CHECK_POINTER_ALLOC(*config, error);

        (*config)->nb_volume_scanner_thread = 5;
	(*config)->chunk_crawler_sleep_time = 100;
	(*config)->chunk_checker_sleep_time = 100;

        return TRUE;
}
