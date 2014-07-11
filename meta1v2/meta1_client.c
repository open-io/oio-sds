#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.meta1.client"
#endif

#include <stddef.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "./meta1_remote.h"

static addr_info_t addr;
static gboolean flag_list = FALSE;

static const char *
meta1_usage(void)
{
        return "IP:PORT list";
}

static void
meta1_client_list(void)
{
	gchar url[64];
	grid_addrinfo_to_string(&addr, url, sizeof(url));
	
	GRID_INFO("List of prefixes managed by this meta1 %s",url);
	GError *err = NULL;
        gchar **result;
        guint len =0;

	meta1v2_remote_get_prefixes(&addr, &err, &result);

	if (err != NULL) {
                GRID_WARN("META1 request error (%d) : %s", err->code, err->message);
                g_clear_error(&err);
        } else {
		if ( result == NULL || g_strv_length(result) == 0) {
			GRID_WARN("NO prefix managed by this meta1 %s.",url);
			return;
		}
                len = g_strv_length(result);
                guint i=0,done=0;
                for (i=len; i >0 ; i--,done++) {
                        g_print("%s ",result[i-1]);
			if ( (done+1) % 15 == 0 && done!= 0 )
				g_print("\n");
                }
		g_print("\n");
		GRID_INFO("This meta1 %s managed %d prefixes",url,len);

        }
	GRID_INFO("End of list");

	

}

static void
meta1_action(void)
{
	if (flag_list) {
		meta1_client_list();
	}
}

static struct grid_main_option_s *
meta1_get_options(void)
{
        static struct grid_main_option_s meta1_options[] = {
                {NULL, 0, {.i=0}, NULL}
        };
        return meta1_options;
}

static void
meta1_specific_fini(void)
{
}



static void
meta1_set_defaults(void)
{
        memset(&addr, 0, sizeof(addr));
}

static gboolean
meta1_configure(int argc, char **argv)
{
	const gchar *command;

	if (argc < 2) {
		GRID_WARN("Not enough options, see usage.");
		return FALSE;
	}

	if (!grid_string_to_addrinfo(argv[0], NULL, &addr)) {
                GRID_WARN("Invalid address : (%d) %s", errno, strerror(errno));
                return FALSE;
        }

	command = argv[1];
	if (!g_ascii_strcasecmp(command, "list")) {
		flag_list = TRUE;
        	return TRUE;
	}

	GRID_WARN("Invalid command, see usage.");
	return FALSE;
}


static void
meta1_specific_stop(void)
{
        GRID_TRACE("STOP!");
}


static struct grid_main_callbacks meta1_callbacks =
{
        .options = meta1_get_options,
        .action = meta1_action,
        .set_defaults = meta1_set_defaults,
        .specific_fini = meta1_specific_fini,
        .configure = meta1_configure,
        .usage = meta1_usage,
        .specific_stop = meta1_specific_stop,
};


int
main(int argc, char ** argv)
{
        return grid_main(argc, argv, &meta1_callbacks);
}

