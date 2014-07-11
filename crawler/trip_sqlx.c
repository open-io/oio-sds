#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.crawler.trip_container"
#endif //G_LOG_DOMAIN

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo.h>
#include <glib.h>

#include "lib/crawler_constants.h"
#include "lib/lib_trip.h"
#include "lib/trip_common.h"
#include "lib/crawler_tools.h"
#include "lib/dir_explorer.h"


#define SQLX_TYPE "sqlx"


// FIX TODO: trip_sqlx and trip_container: the SAME code except trip_name, "xattr url", verif function on trip_next()...

static gchar* trip_name                = "trip_sqlx";
static gchar* source_cmd_opt_name      = "s";
static gchar* infinite_cmd_opt_name    = "infinite";
static gchar* trip_occur_format_string = "(sssss)";

static gchar  sqlx_url[LIMIT_LENGTH_URL] = "";
static gchar* source_directory_path      = NULL;
static gboolean infinite                 = FALSE;

static dir_explorer_t     dir_explorer_handle;
static sqlx_repository_t *global_repo = NULL;




gboolean extract_from_bdd(gchar* file_path, gchar** type_, gchar** seq, gchar** cid)
{
	gchar* container_name = NULL;
	gchar** v = NULL;
	gboolean rc = FALSE;

	TRIP_INFO("file_path=%s", file_path);	

	gchar* file_name = basename(file_path);

	// type
	if (type_) {
		gchar* e = NULL;
		if (!(e = g_strrstr(file_name, ".sqlx.")))
			*type_ = g_strdup("");
		else
		    *type_ = g_strdup(e+1);
	}

	// properties admin
	container_name = tc_sqliterepo_admget(global_repo, *type_, file_name, "container_name");
    if (container_name==NULL)
        goto on_error;

	v = g_strsplit(container_name, "@", 0);	
	if (g_strv_length(v) < 2)
		goto on_error;

	if (seq) *seq = g_strdup(v[0]);
	if (cid) *cid = g_strdup(v[1]);


	TRIP_INFO("file_path=%s: file_name=[%s], *type_=[%s], container_name=[%s], *seq=[%s], *cid=[%s]", 
				file_path, file_name, *type_, container_name, *seq, *cid);	

	rc = TRUE;
	goto on_success;

on_error:
	if (v)
		g_strfreev(v);
	if (type_) {
		if (*type_) {
			g_free(*type_);
			*type_ = NULL;
		}
	}
	rc = FALSE;

on_success:
	if (v)
        g_strfreev(v);
	if (container_name) 
		g_free(container_name);


	return rc;
}







	int
trip_progress(void)
{
	return dir_progress(&dir_explorer_handle);
}

	int
trip_start(int argc, char** argv)
{
	GError *err = NULL;
	memset(sqlx_url, 0, sizeof(sqlx_url));
	memset(&dir_explorer_handle, 0, sizeof(dir_explorer_t));

	/* Infinite parameter extraction */
	gchar* temp_infinite = NULL;
	if (NULL != (temp_infinite = get_argv_value(argc, argv, trip_name, infinite_cmd_opt_name))) {
		infinite = metautils_cfg_get_bool(temp_infinite, FALSE);
		g_free(temp_infinite);
	}
	/* ------- */

	/* Source directory path extraction */
	if (NULL == (source_directory_path = get_argv_value(argc, argv, trip_name, source_cmd_opt_name))) {
		GRID_ERROR("Bad or missing -%s.%s argument", trip_name, source_cmd_opt_name);
		return EXIT_FAILURE;
	}
	/* ------- */

	/* Meta2 URL extraction */
	if (getxattr(source_directory_path, "user.sqlx_server.address", sqlx_url, sizeof(sqlx_url)) <= 0) {
		GRID_ERROR("Cannot get xattr parameters of repository [%s]: (errno %d) %s",
				source_directory_path, errno, g_strerror(errno));
		return EXIT_FAILURE;
	}

	if (!g_strcmp0("", sqlx_url)) {
		GRID_ERROR("Bad xattr azttribute (bad repository?) about repository [%s]", source_directory_path);
		return EXIT_FAILURE;
	}
	/* ------- */

	err = tc_sqliterepo_initRepository(source_directory_path, SQLX_TYPE, &global_repo);
	if (err) {
		TRIP_ERROR("Failed on repository init [%s] : %s", source_directory_path, err->message);
		if (global_repo)
			sqlx_repository_clean(global_repo);
		g_clear_error(&err);
		return EXIT_FAILURE;
	}

	err = dir_explore(source_directory_path, &dir_explorer_handle);
	if (err) {
		GRID_ERROR("Failed during exploring repository [%s]: %s", source_directory_path, err->message);
		g_clear_error(&err);
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

	static gboolean
_reset_infinite(void)
{
	GError *err = NULL;
	sleep(1);

	dir_explorer_clean(&dir_explorer_handle);
	err = dir_explore(source_directory_path, &dir_explorer_handle);
	if (err) {
		TRIP_ERROR("Failed to reset dir_explorer [%s]: %s",
				source_directory_path, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	return TRUE;
}

	static GVariant*
_sub_trip_next()
{
	gchar* file_path = NULL;
	gchar *type_ = NULL;
	gchar* seq = NULL;
	gchar* cid = NULL;

	file_path = dir_next_file(&dir_explorer_handle, NULL);
	while (file_path != NULL) {
		TRIP_INFO("file_path=%s,", file_path);
		if (extract_from_bdd(file_path, &type_, &seq, &cid)) {				
			TRIP_INFO("Pass container [%s|%s|%s|%s|%s] to actions", 
						/*source_directory_path*/file_path, seq, cid, type_, sqlx_url);
			GVariant* ret = g_variant_new(trip_occur_format_string, 
						/*source_directory_path*/file_path, seq, cid, type_, sqlx_url);
			g_free(file_path);
			if (type_) g_free(type_);
			if (seq)   g_free(seq);
			if (cid)   g_free(cid);
			return ret;
		}
		g_free(file_path);
		file_path = dir_next_file(&dir_explorer_handle, NULL);
	}

	// file_path is NULL, we can restart at the beginning
	if (!infinite || !_reset_infinite()) 
		return NULL;
	
	return NULL;
}

	GVariant*
trip_next(void)
{
	do {
        GVariant* occur = _sub_trip_next();
		if (occur)
			return occur;
	} while (TRUE == infinite);

	return NULL;
}

	void
trip_end(void)
{
	tc_sqliterepo_free(&global_repo);
	dir_explorer_clean(&dir_explorer_handle);
	if (NULL!= source_directory_path)
		g_free(source_directory_path);
}
