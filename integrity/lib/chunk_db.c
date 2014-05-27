#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "integrity.lib.chunk_db"
#endif

#include <string.h>

#include <db.h>

#include <glib/gstdio.h>

#include <metautils/lib/metautils.h>

#include "./chunk_db.h"
#include "./check.h"

/**
 Convert a GByteArray to a string and add it to a list (GFunc to be used in g_slist_foreach)

 @param data the GByteArray
 @param user_data a double pointer to a GSList in which to add the string
 */
static void
_convert_byte_array_to_string(gpointer data, gpointer user_data)
{
	GByteArray *gba;
	GSList** list;

	if (data == NULL || user_data == NULL)
		return;

	gba = (GByteArray*)data;
	list = (GSList**)user_data;
	
	*list = g_slist_prepend(*list, g_strndup((gchar*)gba->data, gba->len));

	g_byte_array_free(gba, TRUE);
}

static GByteArray*
_str2gba(const gchar *str)
{
	GByteArray *gba;
	int len;

	len = strlen(str);
	gba = g_byte_array_sized_new(len);
	g_byte_array_append(gba, (guint8*)str, len);
	return gba;
}

static GByteArray*
_get_content_key(const gchar* str_cid, const gchar* str_path)
{
	GByteArray *gba;

	gba = g_byte_array_new();
	g_byte_array_append(gba, (guint8*)str_cid, strlen(str_cid));
	g_byte_array_append(gba, (guint8*)":", 1);
	g_byte_array_append(gba, (guint8*)str_path, strlen(str_path));
	return gba;
}

static GByteArray*
_get_container_key(const gchar* container_id)
{
	return _str2gba(container_id);
}

static gchar*
_get_content_db_path(const gchar* volume_root)
{
	return g_strconcat(volume_root, G_DIR_SEPARATOR_S, CONTENT_DB_NAME, NULL);
}

static gchar*
_get_tmp_content_db_path(const gchar* volume_root)
{
	gchar *content_db_path = NULL;
	gchar *result = NULL;

	content_db_path = _get_content_db_path(volume_root);
	result = g_strdup_printf("%s-%i", content_db_path, getpid());
	g_free(content_db_path);
	return result;
}

static gchar*
_get_container_db_path(const gchar* volume_root)
{
	return g_strconcat(volume_root, G_DIR_SEPARATOR_S, CONTAINER_DB_NAME, NULL);
}

static gchar*
_get_tmp_container_db_path(const gchar* volume_root)
{
	gchar *container_db_path = NULL;
	gchar *result = NULL;

	container_db_path = _get_container_db_path(volume_root);
	result = g_strdup_printf("%s-%i", container_db_path, getpid());
	g_free(container_db_path);
	return result;
}

/**
 Berkley db error listener. Just use log4c ERROR.
 */
static void
_db_err_listener(const DB_ENV *dbenv, const char *errpfx, const char *msg)
{
	(void)dbenv;
	(void)errpfx;

	ERROR(msg);
}

/**
 Open a Berkley db database and create it if it does not exist
 Database use the BTREE type and allows key duplicates

 @param db_path the full path to the db file
 @param db_handle the DB* which will be allocated
 @param error

 @return TRUE or FALSE if en error occured (error is set)
 */
static gboolean
_open_db(const gchar* db_path, DB** db_handle, GError** error)
{
	int rc;

	/* Init db handle */
	rc = db_create(db_handle, NULL, 0);
	if (rc != 0) {
		GSETERROR(error, "Error from Berkley DB : %s", db_strerror(rc));
		GSETERROR(error, "Failed to init db handle");
		return FALSE;
	}

	(*db_handle)->set_errcall(*db_handle, _db_err_listener);
	(*db_handle)->set_flags(*db_handle, DB_DUPSORT);

	/* Open database */
	rc = (*db_handle)->open(*db_handle, NULL, db_path, NULL, DB_BTREE, DB_CREATE, 0);
	if (rc != 0) {
		GSETERROR(error, "Error from Berkley DB : %s", db_strerror(rc));
		GSETERROR(error, "Failed to open db [%s]", db_path);
		(*db_handle)->close(*db_handle, 0);
		return FALSE;
	}

	return TRUE;
}

/**
 Get a list of values matching the given key from a Berkley db

 @param db_path the full path to the db
 @param key the key to search in the db
 @param values the list which will be filled with values matching the key (in GByteArray format)
 @param error

 @return TRUE or FALSE if en error occured (error is set)
 */
static gboolean
_get_from_db(const gchar* db_path, GByteArray* key, GSList **values, GError **error)
{
	DB *db_handle = NULL;
	DBC *db_cursor = NULL;
	DBT db_key, db_value;
	int rc;

	*values = NULL;
	memset(&db_key, 0, sizeof(DBT));
	memset(&db_value, 0, sizeof(DBT));

	/* Open db */
	if (!_open_db(db_path, &db_handle, error)) {
		GSETERROR(error, "Failed to open db [%s]", db_path);
		return FALSE;
	}

	/* Open cursor */
	rc = db_handle->cursor(db_handle, NULL, &db_cursor, 0);
	if (rc != 0) {
		GSETERROR(error, "Error from Berkley DB : %s", db_strerror(rc));
		GSETERROR(error, "Failed to create cursor");
		db_handle->close(db_handle, 0);
		return FALSE;
	}

	/* Request db */
	db_key.data = key->data;
	db_key.size = key->len;
	rc = db_cursor->c_get(db_cursor, &db_key, &db_value, DB_SET);
	TRACE("db_cursor->c_get(...,DB_SET) = %d", rc);

	if (rc != 0) {
		db_cursor->c_close(db_cursor);
		db_handle->close(db_handle, 0);
		if (rc == DB_NOTFOUND)
			return TRUE;
		GSETERROR(error, "Error from Berkley DB : %s", db_strerror(rc));
		GSETERROR(error, "Failed to request db [%s]", db_path);
		return FALSE;
	}
		
        while (rc != DB_NOTFOUND) {
		*values = g_slist_prepend(*values, g_byte_array_append(g_byte_array_new(), db_value.data, db_value.size));

		/* Request db */
		db_key.data = key->data;
		db_key.size = key->len;
                rc = db_cursor->c_get(db_cursor, &db_key, &db_value, DB_NEXT_DUP);
		TRACE("db_cursor->c_get(...,DB_NEXT_DUP) = %d", rc);

		if (rc != 0 && rc != DB_NOTFOUND) {
			GSETERROR(error, "Error from Berkley DB : %s", db_strerror(rc));
			GSETERROR(error, "Failed to request db [%s]", db_path);
			db_cursor->c_close(db_cursor);
			db_handle->close(db_handle, 0);
			return FALSE;
		}	
        }

        db_cursor->c_close(db_cursor);
	db_handle->close(db_handle, 0);

	return TRUE;
}

/**
 Add a key/value pair to a Berkley db
 */
static gboolean
_add_to_db(const gchar* db_path, GByteArray* key, GByteArray* value, GError **error)
{
	DB *db_handle = NULL;
	DBT db_key, db_value;
	int rc;

	/* Open db */
	if (!_open_db(db_path, &db_handle, error)) {
		GSETERROR(error, "Failed to open db [%s]", db_path);
		return FALSE;
	}

	/* Prepare key and value records */
	memset(&db_key, 0, sizeof(DBT));
	memset(&db_value, 0, sizeof(DBT));

	db_key.data = key->data;
	db_key.size = key->len;

	db_value.data = value->data;
	db_value.size = value->len;

	/* Put in database */
	rc = db_handle->put(db_handle, NULL, &db_key, &db_value, DB_NODUPDATA);
	TRACE("db_handle->put(...,DB_NODUPDATA) = %d", rc);
	if (rc != 0 && rc != DB_KEYEXIST) {
		GSETERROR(error, "Failed to add new record to db [%s] : %s", db_path, db_strerror(rc));
		db_handle->close(db_handle, 0);
		return FALSE;
	}

	/* Close db */
	db_handle->close(db_handle, 0);

	return TRUE;
}

static gboolean
_run_db(const gchar* db_path, GError **error, gboolean (*cb)(GByteArray *gba_k, GByteArray *gba_v))
{
	gboolean result;
	DB *db_handle = NULL;
	DBC *db_cursor = NULL;
	DBT db_key, db_value;
	int rc = -1;

	/* Open db */
	if (!_open_db(db_path, &db_handle, error)) {
		GSETERROR(error, "Failed to open db [%s]", db_path);
		return FALSE;
	}

	/* Open cursor */
	rc = db_handle->cursor(db_handle, NULL, &db_cursor, 0);
	if (rc != 0) {
		GSETERROR(error, "Error from Berkley DB : %s", db_strerror(rc));
		GSETERROR(error, "Failed to create cursor");
		db_handle->close(db_handle, 0);
		return FALSE;
	}

	bzero(&db_key, sizeof(db_key));
	bzero(&db_value, sizeof(db_value));
	rc = db_cursor->c_get(db_cursor, &db_key, &db_value, DB_FIRST);
	TRACE("db_cursor->c_get(...,DB_FIRST) = %d", rc);
	if (rc != 0) {
        	db_cursor->c_close(db_cursor);
		db_handle->close(db_handle, 0);
		if (rc == DB_NOTFOUND)
			return TRUE;
		GSETERROR(error, "Error from Berkley DB : %s", db_strerror(rc));
		GSETERROR(error, "Failed to request db [%s]", db_path);
		return FALSE;
	}

	for (;;) {
		GByteArray *gba_k, *gba_v;
		gboolean rc_cb;

		gba_k = g_byte_array_append(g_byte_array_new(), db_key.data, db_key.size);
		gba_v = g_byte_array_append(g_byte_array_new(), db_value.data, db_value.size);
		rc_cb = cb(gba_k, gba_v);
		g_byte_array_free(gba_k, TRUE);
		g_byte_array_free(gba_v, TRUE);

		(void) rc_cb;

		/* Request db */
		bzero(&db_key, sizeof(db_key));
		bzero(&db_value, sizeof(db_value));
		rc = db_cursor->c_get(db_cursor, &db_key, &db_value, DB_NEXT);
		TRACE("db_cursor->c_get(...,DB_NEXT_DUP) = %d", rc);

		if (rc == DB_NOTFOUND) {
			result = TRUE;
			break;
		}
		if (rc != 0) {
			GSETERROR(error, "Error from Berkley DB : %s", db_strerror(rc));
			GSETERROR(error, "Failed to request db [%s]", db_path);
			result = FALSE;
			break;
		}
	}

        db_cursor->c_close(db_cursor);
	db_handle->close(db_handle, 0);
	return result;
}

/* ------------------------------------------------------------------------- */

gboolean
add_chunk_to_db(const gchar* volume_root, const gchar* chunk_path, const gchar* content_name,
		const gchar* container_id, GError **error)
{
	char *content_db_path = NULL;
	char *container_db_path = NULL;
	GByteArray* key, *value;
	gboolean rc;

	CHECK_ARG_POINTER(volume_root, error);
	CHECK_ARG_POINTER(chunk_path, error);
	CHECK_ARG_POINTER(content_name, error);
	CHECK_ARG_POINTER(container_id, error);

	value = _str2gba(chunk_path);

	/* Insertion in the CONTENT table */
	content_db_path = _get_tmp_content_db_path(volume_root);
	key = _get_content_key(container_id, content_name);
	rc = _add_to_db(content_db_path, key, value, error);
	g_byte_array_free(key, TRUE);
	g_free(content_db_path);

	if (!rc) {
		ERROR((*error)->message);
		GSETERROR(error, "Failed to put data in content db");
		g_byte_array_free(value, TRUE);
		return FALSE;
	}

	/* Insertion in the CONTAINER table */
	container_db_path = _get_tmp_container_db_path(volume_root);
	key = _get_container_key(container_id);
	rc = _add_to_db(container_db_path, key, value, error);
	g_byte_array_free(key, TRUE);
	g_free(container_db_path);

	if (!rc) {
		ERROR((*error)->message);
		GSETERROR(error, "Failed to put data in container db");
		g_byte_array_free(value, TRUE);
		return FALSE;
	}

	g_byte_array_free(value, TRUE);
	return TRUE;
}

gboolean
get_content_chunks(const gchar* volume_root, const gchar* container_id, const gchar* content_name,
		GSList **list_chunk, GError **error)
{
	gchar* db_path = NULL;
	GByteArray *key = NULL;
	GSList *result = NULL;
	int rc;

	CHECK_ARG_POINTER(volume_root, error);
	CHECK_ARG_POINTER(content_name, error);
	CHECK_ARG_POINTER(list_chunk, error);

	db_path = _get_content_db_path(volume_root);
	key = _get_content_key(container_id, content_name);
	rc = _get_from_db(db_path, key, &result, error);
	g_byte_array_free(key, TRUE);
	g_free(db_path);

	if (!rc) {
		GSETERROR(error, "Failed to request db");
		return FALSE;
	}

	if (TRACE_ENABLED()) {
		TRACE("Found %u chunks for container [%s]:[%s]", g_slist_length(result), container_id, content_name);
	}

	*list_chunk = NULL;
	g_slist_foreach(result, _convert_byte_array_to_string, list_chunk);
	g_slist_free(result);
	return TRUE;
}

gboolean
get_container_chunks(const gchar* volume_root, const gchar* container_id, GSList **list_chunk, GError **error)
{
	gchar* db_path = NULL;
	GByteArray *key = NULL;
	GSList *result = NULL;
	int rc;

	CHECK_ARG_POINTER(volume_root, error);
	CHECK_ARG_POINTER(container_id, error);
	CHECK_ARG_POINTER(list_chunk, error);

	db_path = _get_container_db_path(volume_root);
	key = _get_container_key(container_id);
	rc = _get_from_db(db_path, key, &result, error);
	g_byte_array_free(key, TRUE);
	g_free(db_path);

	if (!rc) {
		GSETERROR(error, "Failed to request db");
		return FALSE;
	}

	if (TRACE_ENABLED()) {
		TRACE("Found %u chunks for container [%s]", g_slist_length(result), container_id);
	}

	*list_chunk = NULL;
	g_slist_foreach(result, _convert_byte_array_to_string, list_chunk);
	g_slist_free(result);
	return TRUE;
}

gboolean
list_container_chunks(const gchar* volume_root, GError **error, gboolean (*cb)(GByteArray *gba_k, GByteArray *gba_v))
{
	gchar* db_path = NULL;
	int rc;

	CHECK_ARG_POINTER(volume_root, error);
	CHECK_ARG_POINTER(cb, error);

	db_path = _get_container_db_path(volume_root);
	rc = _run_db(db_path, error, cb);
	g_free(db_path);

	if (rc)
		return TRUE;
	GSETERROR(error, "DB traversal error");
	return FALSE;
}

gboolean
list_content_chunks(const gchar* volume_root, GError **error, gboolean (*cb)(GByteArray *gba_k, GByteArray *gba_v))
{
	gchar* db_path = NULL;
	int rc;

	CHECK_ARG_POINTER(volume_root, error);
	CHECK_ARG_POINTER(cb, error);

	db_path = _get_content_db_path(volume_root);
	rc = _run_db(db_path, error, cb);
	g_free(db_path);

	if (rc)
		return TRUE;
	GSETERROR(error, "DB traversal error");
	return FALSE;
}

void
prepare_chunks_db(const gchar* volume_root)
{
	gchar *db_content_path = NULL;
	gchar *db_container_path = NULL;

	db_content_path = _get_tmp_content_db_path(volume_root);
	db_container_path = _get_tmp_container_db_path(volume_root);

	if (g_file_test(db_content_path, G_FILE_TEST_EXISTS)) {
		INFO("Removing previously created tmp chunk content db [%s]", db_content_path);
		g_remove(db_content_path);
	}

	if (g_file_test(db_container_path, G_FILE_TEST_EXISTS)) {
		INFO("Removing previously created tmp chunk container db [%s]", db_container_path);
		g_remove(db_container_path);
	}

	g_free(db_content_path);
	g_free(db_container_path);
}

void
commit_chunks_db(const gchar* volume_root)
{
	gchar *db_content_path = NULL;
	gchar *db_container_path = NULL;
	gchar *db_tmp_content_path = NULL;
	gchar *db_tmp_container_path = NULL;

	db_tmp_content_path = _get_tmp_content_db_path(volume_root);
	db_tmp_container_path = _get_tmp_container_db_path(volume_root);
	db_content_path = _get_content_db_path(volume_root);
	db_container_path = _get_container_db_path(volume_root);

	g_rename(db_tmp_content_path, db_content_path);
	g_rename(db_tmp_container_path, db_container_path);

	g_free(db_tmp_content_path);
	g_free(db_tmp_container_path);
	g_free(db_content_path);
	g_free(db_container_path);
}

void
rollback_chunks_db(const gchar* volume_root)
{
	gchar *db_content_path = NULL;
	gchar *db_container_path = NULL;

	db_content_path = _get_tmp_content_db_path(volume_root);
	db_container_path = _get_tmp_container_db_path(volume_root);

	g_remove(db_content_path);
	g_remove(db_container_path);

	g_free(db_content_path);
	g_free(db_container_path);
}
