#include <sys/stat.h>
#include <sys/types.h>
#include <glib.h>
#include <db.h>

#include <test-dept.h>

#include <metautils/lib/metautils.h>

#include "chunk_db.h"

#define VOLUME_ROOT "chunk_db_test_fake_vol_root"
#define CHUNK_PATH VOLUME_ROOT"/aa/bb/AABBCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
#define CHUNK_PATH2 VOLUME_ROOT"/aa/bb/AABBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDDDD"
#define CONTENT_NAME "content"
#define CONTAINER_ID "AAAAAAAAAAAAAABBBBBBBBBBBBBBBCCCCCCCCCCCCCCC33333333333333333EEEEEEEEEEEEEEE"

void setup()
{
	log4c_init();

	mkdir(VOLUME_ROOT, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);

	return;
}

void teardown()
{
	gchar* content_db_path;
	gchar* container_db_path;

	log4c_fini();

	content_db_path = g_strdup_printf("%s/%s", VOLUME_ROOT, CONTENT_DB_NAME);
	container_db_path = g_strdup_printf("%s/%s", VOLUME_ROOT, CONTAINER_DB_NAME);

#if 1
	unlink(content_db_path);
	unlink(container_db_path);
	rmdir(VOLUME_ROOT);
#endif

	g_free(content_db_path);
	g_free(container_db_path);

	return;
}

void test_add_chunk_to_db_args_null()
{
	GError *error = NULL;

	test_dept_assert_false(add_chunk_to_db(NULL, CHUNK_PATH, CONTENT_NAME, CONTAINER_ID, &error));
	test_dept_assert_true(error);

	g_clear_error(&error);
	error = NULL;

	test_dept_assert_false(add_chunk_to_db(VOLUME_ROOT, NULL, CONTENT_NAME, CONTAINER_ID, &error));
	test_dept_assert_true(error);

	g_clear_error(&error);
	error = NULL;

	test_dept_assert_false(add_chunk_to_db(VOLUME_ROOT, CHUNK_PATH, NULL, CONTAINER_ID, &error));
	test_dept_assert_true(error);

	g_clear_error(&error);
	error = NULL;

	test_dept_assert_false(add_chunk_to_db(VOLUME_ROOT, CHUNK_PATH, CONTENT_NAME, NULL, &error));
	test_dept_assert_true(error);
}

void test_add_chunk_to_db()
{
	GError *error = NULL;
	gchar* content_db_path = NULL;
	gchar* container_db_path = NULL;
	DB* content_db, *container_db;
	DBT key, value;
	DBC *db_cursor = NULL;
	int rc;

	test_dept_assert_true(add_chunk_to_db(VOLUME_ROOT, CHUNK_PATH, CONTENT_NAME, CONTAINER_ID, &error));

	content_db_path = g_strdup_printf("%s/%s", VOLUME_ROOT, CONTENT_DB_NAME);
	container_db_path = g_strdup_printf("%s/%s", VOLUME_ROOT, CONTAINER_DB_NAME);

	/* init db handles */
	test_dept_assert_equals_int(0, db_create(&content_db, NULL, 0));
	test_dept_assert_equals_int(0, db_create(&container_db, NULL, 0));


	/* Get on content db */
	test_dept_assert_equals_int(0, content_db->open(content_db, NULL, content_db_path, NULL, DB_BTREE, 0, 0));
	test_dept_assert_equals_int(0, content_db->cursor(content_db, NULL, &db_cursor, 0));
	
	memset(&key, 0, sizeof(DBT));
	memset(&value, 0, sizeof(DBT));

	key.data = CONTENT_NAME;
	key.size = strlen(CONTENT_NAME)+1;

	rc = db_cursor->c_get(db_cursor, &key, &value, DB_SET);
	test_dept_assert_equals_int(0, rc);
	while (rc != DB_NOTFOUND) {
		test_dept_assert_equals_string((gchar*)value.data, CHUNK_PATH);
		rc = db_cursor->c_get(db_cursor, &key, &value, DB_NEXT_DUP);
	}

	db_cursor->c_close(db_cursor);
	content_db->close(content_db, 0);


	/* Get on container db */
	test_dept_assert_equals_int(0, container_db->open(container_db, NULL, container_db_path, NULL, DB_BTREE, 0, 0));
	test_dept_assert_equals_int(0, container_db->cursor(container_db, NULL, &db_cursor, 0));

	memset(&key, 0, sizeof(DBT));
	memset(&value, 0, sizeof(DBT));

	key.data = CONTAINER_ID;
	key.size = strlen(CONTAINER_ID)+1;

	rc = db_cursor->c_get(db_cursor, &key, &value, DB_SET);
	test_dept_assert_equals_int(0, rc);
	while (rc != DB_NOTFOUND) {
		test_dept_assert_equals_string((gchar*)value.data, CHUNK_PATH);
		rc = db_cursor->c_get(db_cursor, &key, &value, DB_NEXT_DUP);
	}

	db_cursor->c_close(db_cursor);
	container_db->close(container_db, 0);
}

void
test_get_content_chunks_args_null()
{
	GError *error = NULL;
	GSList *list_chunk = NULL;

	test_dept_assert_false(get_content_chunks(NULL, CONTENT_NAME, &list_chunk, &error));
	test_dept_assert_true(error);

	test_dept_assert_false(get_content_chunks(VOLUME_ROOT, NULL, &list_chunk, &error));
	test_dept_assert_true(error);

	test_dept_assert_false(get_content_chunks(VOLUME_ROOT, CONTENT_NAME, NULL, &error));
	test_dept_assert_true(error);
}

void
test_get_content_chunks()
{
	GError *error = NULL;
	GSList *list_chunk = NULL;

	/* Add two chunks from the same content and container */
	test_dept_assert_true(add_chunk_to_db(VOLUME_ROOT, CHUNK_PATH, CONTENT_NAME, CONTAINER_ID, &error));
	test_dept_assert_true(add_chunk_to_db(VOLUME_ROOT, CHUNK_PATH2, CONTENT_NAME, CONTAINER_ID, &error));

	/* Get chunks and check */
	test_dept_assert_true(get_content_chunks(VOLUME_ROOT, CONTENT_NAME, &list_chunk, &error));
	test_dept_assert_equals_int(2, g_slist_length(list_chunk));
	test_dept_assert_not_equals_string(((char*)g_slist_nth(list_chunk, 0)->data), ((char*)g_slist_nth(list_chunk, 1)->data));
}

void test_get_container_chunks_args_null()
{
	GError *error = NULL;
	GSList *list_chunk = NULL;

	test_dept_assert_false(get_container_chunks(NULL, CONTAINER_ID, &list_chunk, &error));
	test_dept_assert_true(error);

	test_dept_assert_false(get_container_chunks(VOLUME_ROOT, NULL, &list_chunk, &error));
	test_dept_assert_true(error);

	test_dept_assert_false(get_container_chunks(VOLUME_ROOT, CONTAINER_ID, NULL, &error));
	test_dept_assert_true(error);
}

void
test_get_container_chunks()
{
	GError *error = NULL;
	GSList *list_chunk = NULL;

	/* Add two chunks from the same content and container */
	test_dept_assert_true(add_chunk_to_db(VOLUME_ROOT, CHUNK_PATH, CONTENT_NAME, CONTAINER_ID, &error));
	test_dept_assert_true(add_chunk_to_db(VOLUME_ROOT, CHUNK_PATH2, CONTENT_NAME, CONTAINER_ID, &error));

	/* Get chunks and check */
	test_dept_assert_true(get_container_chunks(VOLUME_ROOT, CONTAINER_ID, &list_chunk, &error));
	test_dept_assert_equals_int(2, g_slist_length(list_chunk));
	test_dept_assert_not_equals_string(((char*)g_slist_nth(list_chunk, 0)->data), ((char*)g_slist_nth(list_chunk, 1)->data));
}
