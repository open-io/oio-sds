#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.tools"
#endif

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>

struct register_info_s {
	char *original_str;
	int port;
	struct service_info_s *si;
};

static GSList *list_reginfo;

static void
run(void)
{
	struct register_info_s *ri;
	GError *err;
	GSList *l;

	for (;;) {
		for (l=list_reginfo; l ;l=l->next) {
			ri = l->data;
			err = NULL;
			if (ri->port <= 0) {
				if (!register_namespace_service(ri->si,&err))
					GRID_ERROR("[%s] Registration failed : %s", ri->original_str, gerror_get_message(err));
				else
					GRID_DEBUG("[%s] Registration OK", ri->original_str);
			}
			else {
				guint8 buffer[5120];
				GByteArray *gba;
				gsize s;
				ssize_t rs;
				gchar url[256];
				addr_info_t addr;
				int fd;

				g_snprintf(url,sizeof(url),"127.0.0.1:%d", ri->port);
				if (!l4_address_init_with_url(&addr, url, &err))
					abort();
				fd = addrinfo_connect(&addr, 2000, &err);
				if (fd<0)
					GRID_WARN("[%s] Connection error with : %s", ri->original_str, gerror_get_message(err));
				else {
					do {
						GSList *list_singleton;
						list_singleton = g_slist_prepend(NULL, ri->si);
						gba = service_info_marshall_gba(list_singleton, &err);
						g_slist_free(list_singleton);
					} while (0);

					g_byte_array_prepend(gba, (guint8*)" ", 1);
					g_byte_array_prepend(gba, (guint8*)MSG_SRV_PSH, sizeof(MSG_SRV_PSH)-1);
					g_byte_array_prepend(gba, (guint8*)&(gba->len), 4);

					if (0 > sock_to_write(fd, 2000, gba->data, gba->len, &err))
						GRID_WARN("[%s] Write error with : %s", ri->original_str, gerror_get_message(err));
					else {
						s = 0;
						for (;;) {
							guint32 status;
							rs = sock_to_read(fd,2000,buffer,sizeof(buffer),&err);
							if (rs == -1) {
								GRID_WARN("[%s] read error : %s\n", ri->original_str, gerror_get_message(err));
								break;
							}
							if (rs == 0)
								break;

							s += rs;
							memcpy(&status,buffer+4,4);
							if (status == 200U) {
								GRID_DEBUG("[%s] registration OK (status=%d msg=%.*s)",
									ri->original_str, status, (int)(rs-8), buffer+8);
								break;
							}
							GRID_WARN("[%s] registration failed, %d bytes received from fd=%d (status=%d msg=%.*s)",
								ri->original_str, (int)rs, fd, status, (int)(rs-8), buffer+8);
						}
						if (!s)
							GRID_WARN("[%s] No reply : %s", ri->original_str, gerror_get_message(err));
					}
					g_byte_array_free(gba,TRUE);
					metautils_pclose(&fd);
				}
			}
			if (err)
				g_error_free(err);
		}
		sleep(1);
	}
}

static void
load_config(int argc, char **args)
{
	GError *error_local;
	int i;
	GRegex *regex;

	error_local = NULL;
	regex = g_regex_new("((unix)|(tcp:(.+))):(.+)\\|(.+)\\|(.+:.+)", 0, 0, &error_local);
	if (!regex) {
		GRID_ERROR("Fatal error : wrong regex for internal arguments parsing : %s", gerror_get_message(error_local));
		abort();
	}

	for (i=1; i<argc ;i++) {
		GMatchInfo *match_info;
		struct service_info_s *si;
		struct register_info_s *ri;

		/* try to match the mandatory format */
		match_info = NULL;
		if (!g_regex_match(regex, args[i], 0, &match_info)) {
			g_printerr("[%s] does not match\n", args[i]);
		}
		else {
			gchar *str_how, *str_tcp_port, *str_ns, *str_type, *str_url;

			str_how = g_match_info_fetch(match_info, 1);
			str_tcp_port = g_match_info_fetch(match_info, 4);
			str_ns = g_match_info_fetch(match_info, 5);
			str_type = g_match_info_fetch(match_info, 6);
			str_url = g_match_info_fetch(match_info, 7);

			si = g_try_malloc0(sizeof(struct service_info_s));
			if (!si)
				abort();
			si->score.value = -2;
			si->score.timestamp = 0;
			g_strlcpy(si->ns_name, str_ns, sizeof(si->ns_name));
			g_strlcpy(si->type, str_type, sizeof(si->type));
			if (!l4_address_init_with_url(&(si->addr), str_url, &error_local)) {
				GRID_ERROR("Failed to build the address : %s", gerror_get_message(error_local));
				abort();
			}
			si->tags = g_ptr_array_new();
			service_tag_set_value_macro(service_info_ensure_tag(si->tags, NAME_MACRO_CPU_NAME), NAME_MACRO_CPU_TYPE, NULL);
			service_tag_set_value_macro(service_info_ensure_tag(si->tags, NAME_MACRO_SPACE_NAME), NAME_MACRO_SPACE_TYPE, "/");

			ri = g_try_malloc0(sizeof(struct register_info_s));
			if (!ri)
				abort();
			ri->original_str = g_strdup(args[i]);
			ri->si = si;
			ri->port = (*str_how=='u') ? -1 : atoi(str_tcp_port);

			g_free(str_how);
			g_free(str_ns);
			g_free(str_type);
			g_free(str_url);
			if (str_tcp_port)
				g_free(str_tcp_port);

			list_reginfo = g_slist_prepend(list_reginfo, ri);
		}
	}
}

int
main(int argc, char **argv)
{
	HC_PROC_INIT(argv, GRID_LOGLVL_INFO);

	freopen("/dev/null","r",stdin);
	freopen("/dev/null","a",stdout);
	list_reginfo = NULL;

	GRID_DEBUG("Usage: %s ((unix|tcp:<PORT>):<NS>|<SRVTYPE>|<IP>:<PORT>)...", argv[0]);
	load_config(argc,argv);

	if (!list_reginfo) {
		GRID_ERROR("No service has been configured");
		return 0;
	}

	run();
	return 0;
}

