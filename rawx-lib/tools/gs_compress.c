#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.compress"
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>

#include <metautils/lib/metautils.h>
#include "gs_rawx_tools.h"


char *optarg;
int optind, opterr, optopt;

int flag_verbose = 0;
int flag_quiet = 0;
int flag_help = 0;

gchar *algo = NULL;
gint64 blocksize = DEFAULT_COMPRESSION_BLOCKSIZE;
struct compression_ctx_s* comp_ctx = NULL;
guint32 checksum;
guint32 compressed_size;
gboolean preserve = FALSE;

static void
help(int argc, char **args)
{
	(void) argc;
	g_printerr("gs_compress utility:\n");
	g_printerr("This binary compress a chunk and set all informations\n");
	g_printerr("needed by an httpd rawx to uncompress it\n");
	g_printerr("Usage: %s [OPTION]... chunk_path...\n", args[0]);
	g_printerr("OPTIONS::\n");
	g_printerr("\t -h : displays this help section;\n");
	g_printerr("\t -v : verbose mode, increases debug output;\n");
	g_printerr("\t -p : preserve mode (recommanded);\n");
	g_printerr("\t -a : compression algorithm (lzo/zlib, default zlib)\n");
	g_printerr("\t -b : compression blocksize\n");
}

static int
parse_opt(int argc, char **args)
{
	int opt;

	while ((opt = getopt(argc, args, "hvqpa:b:")) != -1) {
		switch (opt) {
		case 'h':
			flag_help = ~0;
			break;
		case 'v':
			flag_verbose++;
			break;
		case 'p':
			preserve = TRUE;
			PRINT_DEBUG("Preserve mode activated\n");
			break;
		case 'a':
			/* algo */
			IGNORE_ARG('a');
			if (algo) g_free (algo);
			algo = g_ascii_strup(optarg, strlen(optarg));
			PRINT_DEBUG("Algorithm used : [%s]\n",algo);
			break;
		case 'b':
			/* bs */
			IGNORE_ARG('b');
			blocksize = g_ascii_strtoll(optarg, NULL, 10);
			PRINT_DEBUG("Blocksize used : [%"G_GINT64_FORMAT"]\n",blocksize);
			break;
		case 'q':
			flag_quiet = ~0;
			break;
		case '?':
		default:
			PRINT_ERROR("unexpected %c (%s)\n", optopt, strerror(opterr));
			return 0;
		}
	}

	if(!algo) {
		DEBUG("No compression algorithm in args, using ZLIB (default)");
		algo = g_strdup("ZLIB");
	}

	return 1;
}

int
main(int argc, char** args)
{
	int rc = -1;


	if (argc <= 1) {
		help(argc, args);
		return 1;
	}
	if (!parse_opt(argc, args)) {
		help(argc, args);
		return 1;
	}
	if (flag_help) {
		help(argc, args);
		return 0;
	}

	if (optind < argc) {
		GError *local_error = NULL;
		int i;
		for (i = optind; i < argc; i++) {
			PRINT_DEBUG("Going to work with chunk file [%s]\n", args[i]);
			/* Run compression */
			if(compress_chunk(args[i], algo, blocksize, preserve, &local_error) != 1) {
				if(local_error)
					PRINT_ERROR("Failed to compress chunk [%s] :\n%s", args[i], local_error->message);
				else
					PRINT_ERROR("Failed to compress chunk [%s] : no error",args[i]);
			} else {
				PRINT_DEBUG("Chunk [%s] compressed\n",args[i]);
			}
		}
		PRINT_DEBUG("Process done\n");
	}
	return rc;
}
