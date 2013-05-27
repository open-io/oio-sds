/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef  LOG_DOMAIN
# define LOG_DOMAIN "mover.chunk"
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <metautils.h>
#include <metacomm.h>
#include <gridcluster.h>
#include <grid_client.h>

#include "./mover.h"

#ifndef  LIMIT_LENGTH_NSNAME
# define LIMIT_LENGTH_NSNAME 32
#endif

static gchar ns_name[LIMIT_LENGTH_NSNAME+1] = "";
static gchar path_chunk[1024] = "";
static gchar src_rawx_name[1024] = "";
static gchar dst_rawx_name[1024] = "";

static gs_grid_storage_t *gs_client = NULL;
static struct service_info_s *src_rawx = NULL;
static struct service_info_s *dst_rawx = NULL;

static gboolean flag_check_names = TRUE;
static gboolean flag_unlink = TRUE;
static gboolean flag_dereference = TRUE;
static gboolean flag_download = TRUE;
static gboolean flag_fake = FALSE;

struct str_s {
	gchar *ptr;
	gsize size;
};

struct opt_s {
	char *name;
	enum { OT_BOOL=1, OT_INT, OT_INT64, OT_DOUBLE, OT_TIME, OT_STRING } type;
	void *data;
	char *descr;
};

static struct str_s src_rawx_descr = { src_rawx_name, sizeof(src_rawx_name) };
static struct str_s dst_rawx_descr = { dst_rawx_name, sizeof(dst_rawx_name) };

static struct opt_s options[] = {

	{"SrcRawx", OT_STRING, &src_rawx_descr,
		"REQUIRED! Specify the source RAWX"},
	{"DstRawx", OT_STRING, &dst_rawx_descr,
		"REQUIRED! Specify the source RAWX"},

	{"CheckChunkName", OT_BOOL, &flag_check_names,
		"Only manage chunk files whose name complies [A-Fa-f0-9]{64}"},
	{"ChunkUnlink", OT_BOOL, &flag_unlink,
		"Removes each successfully migrated chunk from the RAWX storage"},
	{"ChunkDereference", OT_BOOL, &flag_dereference,
		"Removes each successfully migrated chunk's reference from the META2. Has no effect unless ChunkUnlink=yes"},
	{"ChunkDownload", OT_BOOL, &flag_download,
		"Download each chunk and check its MD5sum"},
	{"DryRun", OT_BOOL, &flag_fake,
		"Only loads the chunks, but does nothing on them"},

	{NULL, 0, NULL, NULL}
};

static void main_usage(void);
static void main_stop(gboolean log);
static const char* main_set_option(const gchar *str_opt);
static void main_init(int argc, char **args);
static void main_fini(void);
static void main_sighandler_stop(int s);
static void main_sighandler_noop(int s);
static void main_install_sighandlers(void);

static gboolean
check_srvinfo(GSList *services, struct service_info_s *si)
{
	gchar vol[512];
	GSList *l;

	for (l=services; l ;l=l->next) {
		struct service_info_s *current = l->data;
		if (0 == memcmp(&(current->addr), &(si->addr), sizeof(si->addr))) {
			if (si->tags) {
				struct service_tag_s *tag0, *tag;
				tag0 = service_info_get_tag(current->tags, "tag.vol");
				if (NULL != tag0) {
					tag = service_info_ensure_tag(si->tags, "tag.vol");
					memset(vol, 0, sizeof(vol));
					service_tag_get_value_string(tag0, vol, sizeof(vol), NULL);
					service_tag_set_value_string(tag, vol);
				}
			}
			return TRUE;
		}
	}

	return FALSE;
}

static struct service_info_s*
load_srvinfo(const gchar *descr)
{
	GError *err = NULL;
	gint i, max;
	struct service_info_s *si;
	gchar **tokens;

	/* Load the service */
	tokens = g_strsplit_set(descr, "|", 0);
	if (!tokens)
		g_error("Split error on [%s]", descr);

	max = g_strv_length(tokens);
	if (max < 3)
		g_error("Insufficiant tokens number in [%s]."
				" At least 4 are expected, pipe-separated as"
				" in 'NS|rawx|127.0.0.1:6000", descr);

	si = g_malloc0(sizeof(struct service_info_s));
	g_strlcpy(si->ns_name, tokens[0], sizeof(si->ns_name)-1);
	g_strlcpy(si->type, tokens[1], sizeof(si->type)-1);
	if (!l4_address_init_with_url(&(si->addr), tokens[2], &err)) {
		g_error("Invalid RAWX address [%s] as found in [%s]",
			tokens[2], descr);
	}
	si->tags = g_ptr_array_sized_new(4);

	for (i=4; i<max; i++) {
		gchar **subtokens;
		struct service_tag_s *tag;

		subtokens = g_strsplit_set(tokens[i], "|", 2);
		if (subtokens && subtokens[0]) {
			tag = service_info_ensure_tag(si->tags, subtokens[0]);
			service_tag_set_value_boolean(tag, TRUE);
			if (subtokens[1])
				service_tag_set_value_string(tag, subtokens[1]);
		}
		g_strfreev(subtokens);
	}

	g_strfreev(tokens);

	return si;
}

static void
main_logger(const gchar *log_domain, GLogLevelFlags log_level,
		const gchar *message, gpointer user_data)
{
	GString *gstr;

	(void) log_domain;
	(void) log_level;
	(void) user_data;

	gstr = g_string_sized_new(1024);

	do {
		GTimeVal gtv;
		struct tm t;
		
		g_get_current_time(&gtv);
		gstr->len = strftime(gstr->str, gstr->allocated_len, "%Y%m%d %H%M%S", localtime_r(&(gtv.tv_sec), &t));
		g_string_append_printf(gstr, " %03ld ", gtv.tv_usec / 1000L);
	} while (0);

	g_string_append(gstr, g_get_prgname());
	g_string_append_printf(gstr, " %d", getpid());

	switch (log_level & G_LOG_LEVEL_MASK) {
		case G_LOG_LEVEL_ERROR:
			g_string_append(gstr, " ERR ");
			break;
		case G_LOG_LEVEL_CRITICAL:
			g_string_append(gstr, " CRI ");
			break;
		case G_LOG_LEVEL_WARNING:
			g_string_append(gstr, " WRN ");
			break;
		case G_LOG_LEVEL_MESSAGE:
			g_string_append(gstr, " MSG ");
			break;
		case G_LOG_LEVEL_INFO:
			g_string_append(gstr, " INF ");
			break;
		case G_LOG_LEVEL_DEBUG:
			g_string_append(gstr, " DBG ");
			break;
		default:
			g_string_append(gstr, " --- ");
			break;
	}

	if (log_domain && *log_domain) {
		g_string_append(gstr, log_domain);
		g_string_append_c(gstr, ' ');
	}
	else
		g_string_append(gstr, "- ");

	g_string_append(gstr, message);
	g_string_append_c(gstr, '\n');

	fputs(gstr->str, stderr);
	g_string_free(gstr, TRUE);
}

void
main_usage(void)
{
	struct opt_s *o;

	g_printerr("Usage: %s [OPTIONS...] VOLUME\n", g_get_prgname());

	g_printerr("\nOPTIONS:\n");
	g_printerr("  -h         help, displays this section\n");
	g_printerr("  -O XOPT    set extra options.\n");

	g_printerr("\nEXTRA OPTIONS with default value:\n");
	for (o=options; o->name ;o++) {
		gchar name[1024];
		if (o->type == OT_BOOL)
			g_snprintf(name, sizeof(name), "%s=%s", o->name, (*((gboolean*)o->data)?"on":"off"));
		else if (o->type == OT_INT)
			g_snprintf(name, sizeof(name), "%s=%d", o->name, *((gint*)o->data));
		else if (o->type == OT_INT64)
			g_snprintf(name, sizeof(name), "%s=%"G_GINT64_FORMAT, o->name, *((gint64*)o->data));
		else if (o->type == OT_TIME)
			g_snprintf(name, sizeof(name), "%s=%ld", o->name, *((time_t*)o->data));
		else if (o->type == OT_DOUBLE)
			g_snprintf(name, sizeof(name), "%s=%f", o->name, *((gdouble*)o->data));
		else if (o->type == OT_STRING) {
			int i_size = ((struct str_s*)o->data)->size;
			g_snprintf(name, sizeof(name), "%s=%.*s", o->name, i_size, ((struct str_s*)o->data)->ptr);
		}

		g_print("\t%s\n\t\t%s\n", name, o->descr);
	}
}

void
main_stop(gboolean log_allowed)
{
	if (log_allowed)
		NOTICE("Stopping rawx-mover!");
}

const char*
main_set_option(const gchar *str_opt)
{
	static gchar errbuff[1024];

	gchar **tokens;
	struct opt_s *opt;

	bzero(errbuff, sizeof(errbuff));

	tokens = g_strsplit(str_opt, "=", 2);
	if (!tokens) {
		g_snprintf(errbuff, sizeof(errbuff), "Invalid option format '%s', expected 'Key=Value'", str_opt);
		return errbuff;
	}
	for (opt=options; opt->name ;opt++) {
		if (0 == g_ascii_strcasecmp(opt->name, tokens[0])) {
			if (opt->type == OT_BOOL) {
				if (!metautils_cfg_get_bool(tokens[1], *((gboolean*)opt->data)))
					g_snprintf(errbuff, sizeof(errbuff), "Invalid boolean value for option '%s'", opt->name);
			}
			else if (opt->type == OT_INT) {
				gint64 i64;
				i64 = g_ascii_strtoll(tokens[1], NULL, 10);
				*((int*)opt->data) = i64;
			}
			else if (opt->type == OT_INT64) {
				gint64 i64;
				i64 = g_ascii_strtoll(tokens[1], NULL, 10);
				*((gint64*)opt->data) = i64;
			}
			else if (opt->type == OT_TIME) {
				gint64 i64;
				i64 = g_ascii_strtoll(tokens[1], NULL, 10);
				*((time_t*)opt->data) = i64;
			}
			else if (opt->type == OT_DOUBLE) {
				*((gdouble*)opt->data) = g_ascii_strtod(tokens[1], NULL);
			}
			else if (opt->type == OT_STRING) {
				struct str_s *str_descr = opt->data;
				g_strlcpy(str_descr->ptr, tokens[1], str_descr->size);
			}
			else
				g_snprintf(errbuff, sizeof(errbuff), "Internal error for option '%s'", opt->name);

			goto exit;
		}
	}
	g_snprintf(errbuff, sizeof(errbuff), "Option '%s' not supported", tokens[0]);

exit:
	g_strfreev(tokens);
	return (*errbuff ? errbuff : NULL);
}

void
main_init(int argc, char **args)
{
	gs_error_t *gserr = NULL;

	bzero(path_chunk, sizeof(path_chunk));
	bzero(ns_name, sizeof(ns_name));
	bzero(src_rawx_name, sizeof(src_rawx_name));
	bzero(dst_rawx_name, sizeof(src_rawx_name));

	do {
		gchar *bn = g_path_get_basename(args[0]);
		g_set_prgname(bn);
		g_free(bn);
	} while (0);

	for (;;) {
		int c = getopt(argc, args, "O:h");
		if (c == -1)
			break;
		switch (c) {
			case 'O':
				if (!optarg) {
					main_usage();
					g_error("Missing '-O' argument");
				}
				else {
					const char *errmsg = main_set_option(optarg);
					if (errmsg) {
						main_usage();
						g_error("Invalid option : %s", errmsg);
					}
				}
				break;
			case 'h':
				main_usage();
				exit(0);
			case '?':
				main_usage();
				g_error("Unexpected option at position %d ('%c')", optind, optopt);
			default:
				main_usage();
				g_error("Unknown option at position %d ('%c')", optind, optopt);
		}
	}

	if (optind != (argc - 1)) {
		main_usage();
		g_error("Invalid argument number optind=%d argc=%d", optind, argc);
	}

	g_strlcpy(path_chunk, args[optind], sizeof(path_chunk)-1);

	src_rawx = load_srvinfo(src_rawx_name);
	dst_rawx = load_srvinfo(dst_rawx_name);

	if (0 != g_ascii_strncasecmp(src_rawx->ns_name, dst_rawx->ns_name, LIMIT_LENGTH_NSNAME))
		g_error("Namespace mismatch between source and target RAWX");

	if (0 == memcmp(&(src_rawx->addr), &(dst_rawx->addr), sizeof(addr_info_t)))
		g_error("Source and target RAWX are the same");

	g_strlcpy(ns_name, src_rawx->ns_name, sizeof(ns_name)-1);

	/* Check the services are knwn in the NS */
	GError *error = NULL;
	GSList *services = list_namespace_services(ns_name, "rawx", &error);
	if (error)
		g_error("Gridagent error : list_ns_services(%s,'rawx') = (%d) %s",
				ns_name, error->code, error->message);
	if (!check_srvinfo(services, src_rawx))
		g_error("Source RAWX unknown in NS=%s", ns_name);
	if (!check_srvinfo(services, dst_rawx))
		g_error("Target RAWX unknown in NS=%s", ns_name);
	g_slist_foreach(services, service_info_gclean, NULL);
	g_slist_free(services);

	gs_client = gs_grid_storage_init2(ns_name, 10000, 60000, &gserr);
	if (!gs_client)
		g_error("Failed to load Invalid RAWX namespace [%s] : %s", ns_name, gs_error_get_message(gserr));
}

void
main_fini(void)
{
	if (gs_client) {
		gs_grid_storage_free(gs_client);
		gs_client = NULL;
	}

	log4c_fini();
}

void
main_sighandler_stop(int s)
{
	main_stop(FALSE);
	signal(s, main_sighandler_stop);
}

void
main_sighandler_noop(int s)
{
	signal(s, main_sighandler_noop);
}

void
main_install_sighandlers(void)
{
	signal(SIGHUP, main_sighandler_stop);
	signal(SIGINT, main_sighandler_stop);
	signal(SIGQUIT, main_sighandler_stop);
	signal(SIGKILL, main_sighandler_stop);
	signal(SIGTERM, main_sighandler_stop);

	signal(SIGPIPE, main_sighandler_noop);
	signal(SIGUSR1, main_sighandler_noop);
	signal(SIGUSR2, main_sighandler_noop);
}

int
main(int argc, char **args)
{
	struct opt_s *o;
	int rc = 0;

	main_install_sighandlers();
	freopen("/dev/null", "r", stdin);
	if (!g_thread_supported ())
		g_thread_init (NULL);
	g_log_set_default_handler(main_logger, NULL);

	main_init(argc, args);

	/* Config abstract */
	g_debug("Moving [%s] with options:", path_chunk);
	for (o=options; o->name ;o++) {
		if (o->type == OT_BOOL)
			g_debug("\t%-24s %s", o->name, (*((gboolean*)o->data)?"on":"off"));
		else if (o->type == OT_INT)
			g_debug("\t%-24s %d", o->name, *((gint*)o->data));
		else if (o->type == OT_INT64)
			g_debug("\t%-24s %"G_GINT64_FORMAT, o->name, *((gint64*)o->data));
		else if (o->type == OT_TIME)
			g_debug("\t%-24s %ld", o->name, *((time_t*)o->data));
		else if (o->type == OT_DOUBLE)
			g_debug("\t%-24s %f", o->name, *((gdouble*)o->data));
		else if (o->type == OT_STRING) {
			int i_size = ((struct str_s*)o->data)->size;
			g_debug("\t%-24s %.*s", o->name, i_size, ((struct str_s*)o->data)->ptr);
		}
	}
	
	if (!g_file_test(path_chunk, G_FILE_TEST_EXISTS|G_FILE_TEST_IS_REGULAR))
		g_message("File %s not found or not a regular file", path_chunk);
	else if (!chunk_path_is_valid(path_chunk))
		g_debug("Skip non-chunk file %s", path_chunk);
	else {
		guint32 flags = 0;
		GError *e;

		flags |= flag_fake ? GS_MOVER_DRYRUN : 0;
		flags |= flag_unlink ? GS_MOVER_UNLINK : 0;
		flags |= flag_download ? GS_MOVER_DOWNLOAD : 0;
		flags |= flag_dereference ? GS_MOVER_DEREFERENCE : 0;

		e = move_chunk(gs_client, path_chunk, src_rawx, dst_rawx, flags);
		if (!(rc = !e)) {
			g_message("MOVE FAILED : code=%d reason=%s", e->code, e->message);
			g_clear_error(&e);
		}
	}

	/* Run statistics */
	main_fini();
	return rc ? 0 : 1;
}

