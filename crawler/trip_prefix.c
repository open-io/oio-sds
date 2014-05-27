#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.crawler.trip_prefix"
#endif //G_LOG_DOMAIN

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <attr/xattr.h>

#include <metautils/lib/metacomm.h>
#include <metautils/lib/metautils.h>
#include <meta1v2/meta1_backend.h>
#include <sqliterepo/sqlx_remote.h>
#include <sqliterepo/sqliterepo.h>

#include <glib.h>

#include "lib/crawler_constants.h"
#include "lib/crawler_tools.h"
#include "lib/lib_trip.h"
#include "lib/dir_explorer.h"
#include "lib/trip_common.h"


// string utilities
static gchar* trip_name                = "trip_prefix";
static gchar* source_cmd_opt_name      = "s";
static gchar* verbose_cmd_opt_name     = "v";
static gchar* allprefix_cmd_opt_name   = "a";
static gchar* infinite_cmd_opt_name    = "infinite";
static gchar* trip_occur_format_string = "(sss)";

// option command line
static gchar *source_directory_path = NULL;  // Directory to explore
static gboolean infinite            = FALSE;
static gboolean bAllPrefix          = FALSE; // mode de test de charge

// config read
static gchar meta1_url[LIMIT_LENGTH_URL] = "";

//bdd name
static int current_bdd_nb      = 0;

// running temp data
static sqlx_repository_t *global_repo = NULL;
static dir_explorer_t dir_explorer_handle;


enum {
	TRIPERR_BADBDD = 1,
	TRIPERR_NOTFILE = 2,
	TRIPERR_META1SLAVE = 3
};

#define TRIPERR_ALLOC_AND_FORMAT(/*gchar**/prefix, /*int*/ errorCode) {\
	gchar* tmp = g_malloc0(sizeof(gchar) * 8); \
	g_snprintf(tmp, 9, "R%03d", errorCode);\
	prefixCt = tmp; }

static gboolean
meta1_IsMaster(gchar* bddname)
{
	GError* err = NULL;
	gboolean master = FALSE;
	struct sqlx_name_s n;
	GByteArray* req = NULL;
	struct client_s *client;
	gchar* message = NULL;

	// received data function
	gboolean on_reply(gpointer ctx, MESSAGE reply) {
		(void) ctx;
		int status = 0;
		gchar* msg = NULL;

		TRIP_TRACE("%s(%p)", __FUNCTION__, reply);

		if (0 < metaXClient_reply_simple(reply, &status, &msg, NULL)) {
			TRIP_TRACE("%s(%d)(%s)", __FUNCTION__, status, msg);
			message = msg;
		}

		return TRUE;
	}

	// build request
	n.ns   = "";
	n.base = bddname;
	n.type = META1_TYPE_NAME;

	req = sqlx_pack_ISMASTER(&n);
	client = gridd_client_create(meta1_url, req, NULL, on_reply);
	g_byte_array_unref(req);

	// send request and analysed received response
	gridd_client_start(client);
	if (!(err = gridd_client_loop(client))) {
		if (!(err = gridd_client_error(client))) {
			if (message != NULL) {
				if (g_strcmp0(message, "MASTER") == 0)
					master = TRUE;

				TRIP_TRACE("(a)master or slave: [%s]:master=%d", message, master);
				g_free(message);
			}
		} else TRIP_WARN("%s: [%s]: (a)%s", __FUNCTION__, bddname,  err->message);
	}  else TRIP_WARN("%s: [%s]: (b)%s", __FUNCTION__, bddname,  err->message);


	// error received ?
	if (err) {
		TRIP_TRACE("(a)master or slave: :master=%d", master);
		g_clear_error(&err);
	}

	// desallocated
	gridd_client_free(client);


	return master;
}


/**
 * \brief return a percentage about progress trip
 */
int trip_progress(void)
{
	return dir_progress(&dir_explorer_handle);
}


/**
 * \brief first function to call before used trip _next()
 */
int trip_start(int argc, char** argv)
{
	bVerbose = FALSE;
	memset(meta1_url, 0, sizeof(meta1_url));
	current_bdd_nb = 0;
	GError* err = NULL;
	memset(&dir_explorer_handle, 0, sizeof(dir_explorer_t));

	gchar* temp_verbose = NULL;
	if (NULL != (temp_verbose = get_argv_value(argc, argv, trip_name, verbose_cmd_opt_name))) {
		bVerbose = metautils_cfg_get_bool(temp_verbose, FALSE);
		g_free(temp_verbose);
	}

	gchar* temp_allprefix = NULL;
	if (NULL != (temp_allprefix = get_argv_value(argc, argv, trip_name, allprefix_cmd_opt_name))) {
		bAllPrefix = metautils_cfg_get_bool(temp_allprefix, FALSE);
		g_free(temp_allprefix);
	}

	/* Infinite parameter extraction */
	gchar* temp_infinite = NULL;
	if (NULL != (temp_infinite = get_argv_value(argc, argv, trip_name, infinite_cmd_opt_name))) {
		infinite = metautils_cfg_get_bool(temp_infinite, FALSE);
		g_free(temp_infinite);
	}
	/* ------- */

	/* Source directory path extraction */
	if (NULL == (source_directory_path = get_argv_value(argc, argv, trip_name, source_cmd_opt_name))) {
		TRIP_ERROR("Bad or missing -%s.%s argument", trip_name, source_cmd_opt_name);
		return EXIT_FAILURE;
	}
	/* ------- */

	/* Meta2 URL extraction */
	if (getxattr(source_directory_path, "user.meta1_server.address", meta1_url, sizeof(meta1_url)) <= 0) {
		GRID_ERROR("Cannot get xattr parameters of repository [%s]: (errno %d) %s",
				source_directory_path, errno, g_strerror(errno));
		return EXIT_FAILURE;
	}

	if (!g_strcmp0("", meta1_url)) {
		TRIP_ERROR("Bad xattr azttribute (bad repository?) about repository [%s]", source_directory_path);
		g_free(source_directory_path);

		return EXIT_FAILURE;
	}
	/* ------- */

	TRIP_INFO("Initialize and scan directory [%s]... please Wait...", source_directory_path);


	err = tc_sqliterepo_initRepository(source_directory_path, META1_TYPE_NAME, &global_repo);
	if (err) {
		TRIP_ERROR("Failed on repository init [%s] : %s", source_directory_path, err->message);
		if (global_repo)
			sqlx_repository_clean(global_repo);
		g_clear_error(&err);
		return EXIT_FAILURE;
	}

	/* ------- */

	if (bAllPrefix == FALSE) {
		err = dir_explore(source_directory_path, &dir_explorer_handle);
		if (err) {
			TRIP_ERROR("Failed during exploring repository [%s]: %s", source_directory_path, err->message);
			g_clear_error(&err);
			return EXIT_FAILURE;
		}
	} //else total_bdd_nb = 0x10000;

	return EXIT_SUCCESS;
}

/**
 * \brief return a prefix
 */
static GVariant*_sub_trip_next()
{
	gchar* file_path   = NULL;
	gchar* prefixCt    = NULL;
	GVariant* pVariant = NULL;
	gboolean bRetryAnotherPrefix = FALSE;
	
	if (bAllPrefix == TRUE)
		if (current_bdd_nb > 0xFFFF)
			return NULL;

	file_path = dir_next_file(&dir_explorer_handle, NULL);
	while (file_path != NULL) {
		gchar* file_name = basename(file_path);

		if (bAllPrefix == FALSE) {
			if (file_name) {
				// search prefix
				prefixCt = tc_sqliterepo_admget(global_repo, META1_TYPE_NAME, file_name, "base_name");
				if (prefixCt==NULL) {
					TRIPERR_ALLOC_AND_FORMAT(prefixCt, TRIPERR_BADBDD);
				} else {
					// prefix is master for current meta1 ?
					if (meta1_IsMaster(prefixCt) == FALSE) {
						g_free(prefixCt);
						prefixCt = NULL;
						TRIPERR_ALLOC_AND_FORMAT(prefixCt, TRIPERR_META1SLAVE);
					}
				}

			} else  TRIPERR_ALLOC_AND_FORMAT(prefixCt, TRIPERR_NOTFILE);
		} else {
			gchar* tmp = g_malloc0(sizeof(gchar) * 8);
			g_snprintf(tmp, 9, "%04X", current_bdd_nb);
			prefixCt = tmp;
		}

		// prepare data for the crawler returned
		if (bRetryAnotherPrefix == FALSE) {
			TRIP_DEBUG("Pass prefix [%s|%s|%s](num %d) to actions", source_directory_path,
					prefixCt, meta1_url, current_bdd_nb);
			pVariant = g_variant_new(trip_occur_format_string, source_directory_path,
					prefixCt, meta1_url);
		}

		// desalocated
		if (prefixCt) g_free(prefixCt);
		current_bdd_nb++;

		//returned  data
		if (bRetryAnotherPrefix == FALSE)
			return pVariant;


		g_free(file_path);			 
		file_path = dir_next_file(&dir_explorer_handle, NULL);
	}

	return NULL;
	//}

}

/**
 * \function call by crowler, return next prefix
 */
GVariant* trip_next(void)
{
	do {
		GVariant* occur = _sub_trip_next();
		if (occur)
			return occur;
	} while (TRUE == infinite);

	return NULL;
}

/**
 * \brief function call by crawler, call when process ending
 */
void trip_end(void)
{
	dir_explorer_clean(&dir_explorer_handle);
	if (NULL!= source_directory_path)
        g_free(source_directory_path);

	tc_sqliterepo_free(&global_repo);
}

