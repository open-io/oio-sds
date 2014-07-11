#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.lib.meta2_check"
#endif

#include <string.h>
#include <sqlite3.h>

#include <metautils/lib/metautils.h>
#include <rawx-client/lib/rawx_client.h>

#include "./check.h"
#include "./meta2_check.h"
#include "./chunk_check.h"

#define RAWX_CONN_TMEOUT 5
#define RAWX_REQ_TIMEOUT 10

gboolean
meta2_sqlite_maintenance(const gchar* meta2_db_path, GError **error)
{
	sqlite3 *db = NULL;
	int rc;
	char* sqlite_error = NULL;

	CHECK_ARG_POINTER(meta2_db_path, error);
	CHECK_ARG_VALID_DIR(meta2_db_path, error);

        rc = sqlite3_open(meta2_db_path, &db);
	if (rc) {
		GSETERROR(error, "Failed to open database [%s] : %s", meta2_db_path, sqlite3_errmsg(db));
		sqlite3_close(db);
		return FALSE;
	}

	rc = sqlite3_exec(db, "VACUUM;", NULL, 0, &sqlite_error);
	if (rc) {
		GSETERROR(error, "Failed to vacuum databse [%s] : %s", meta2_db_path, sqlite_error);
		sqlite3_free(sqlite_error);
		sqlite3_close(db);
		return FALSE;
	}

	sqlite3_close(db);

	return TRUE;
}

gboolean
check_meta2_chunk(const struct meta2_raw_content_s* raw_content, GSList** broken, GError** error)
{
	rawx_session_t *session;
	struct meta2_raw_chunk_s* raw_chunk = NULL;
	gchar str_url[256];
	gchar str_chunk_id[1024];
	struct content_textinfo_s text_content;
	struct chunk_textinfo_s text_chunk;

	memset(&text_content, 0, sizeof(struct content_textinfo_s));
	memset(&text_chunk, 0, sizeof(struct chunk_textinfo_s));

	CHECK_ARG_POINTER(raw_content, error);
	CHECK_ARG_POINTER(raw_content->raw_chunks, error);
	CHECK_ARG_POINTER(broken, error);

	if (g_slist_length(raw_content->raw_chunks) < 1) {
		GSETERROR(error, "List of raw_chunks in content is empty");
		return FALSE;
	}

	raw_chunk = g_slist_nth_data(raw_content->raw_chunks, 0);

	memset(str_url, '\0', sizeof(str_url));
	addr_info_to_string(&(raw_chunk->id.addr), str_url, sizeof(str_url)-1);

	memset(str_chunk_id, '\0', sizeof(str_chunk_id));
	buffer2str(raw_chunk->id.id, sizeof(hash_sha256_t), str_chunk_id, sizeof(str_chunk_id)-1);

	/* Create http session */
	session = rawx_client_create_session(&(raw_chunk->id.addr), error);
	if (session == NULL) {
		GSETERROR(error, "Failed to create HTTP session to access rawx [%s]", str_url);
		return FALSE;
	}

	rawx_client_session_set_timeout(session, RAWX_CONN_TMEOUT, RAWX_REQ_TIMEOUT);

	if (!rawx_client_get_directory_data(session, raw_chunk->id.id, &text_content, &text_chunk, error)) {
		GSETERROR(error, "Failed to get directory data from rawx [%s] for chunk [%s]", str_url, str_chunk_id);
		rawx_client_free_session(session);
		return FALSE;
	}

	/* destroy session */
	rawx_client_free_session(session);

	if(!check_chunk_referencing(&text_content, &text_chunk, raw_content, broken, error)) {
		GSETERROR(error, "Failed to compare chunk from META2 and chunk from RAWX");
		return FALSE;
	}
		
	return TRUE;
}
