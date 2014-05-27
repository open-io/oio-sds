#include <unistd.h>
#include <glib.h>
#include <test-dept.h>

#include <rawx_client.h>

#include "meta2_checker.h"
#include "stub_headers.h"
#include "../lib/broken_event.h"

#define META2_DB "test_meta2.db"
#define CONTAINER_ID "3A0495C6FF65615D43A078F578809AB8D8BB17A3F841861A6C51D0687EE5E1AF"
#define CHUNK_ID "C678F32385C07EB2A221ABA8C97F38DC46DDBA533121A34F81FDB96A0E4B8FCD"
#define CONTENT_NAME "content"
#define CONTENT_SYSMETADATA "system metadata"
#define CONTENT_SIZE 4096
#define NB_CHUNK 3
#define CONTENT_METADATA ""
#define CHUNK_POSITION 0
#define CHUNK_METADATA ""
#define CHUNK_SIZE 1024
#define CHUNK_HASH "D41D8CD98F00B204E9800998ECF8427E"


gboolean
fake_rawx_client_get_directory_data(rawx_session_t * session, hash_sha256_t chunk_id,
    struct content_textinfo_s *content, struct chunk_textinfo_s *chunk, GError ** error)
{
        content->container_id = CONTAINER_ID;
        content->path = CONTENT_NAME;
        content->size = g_strdup_printf("%d", CONTENT_SIZE);
        content->chunk_nb = g_strdup_printf("%d", NB_CHUNK);
        content->metadata = CONTENT_METADATA;
        content->system_metadata = CONTENT_SYSMETADATA;

        chunk->id = CHUNK_ID;
        chunk->path = CONTENT_NAME;
        chunk->size = g_strdup_printf("%d", CHUNK_SIZE);
        chunk->position = g_strdup_printf("%d", CHUNK_POSITION);
        chunk->hash = CHUNK_HASH;
        chunk->metadata = CHUNK_METADATA;
        chunk->container_id = CONTAINER_ID;

	return TRUE;
}


void
setup()
{
        /* Init log4c */
        log4c_init();
}

void
teardown()
{
	log4c_fini();
}

void test_check_meta2_chunk_args_null()
{
	GError *error = NULL;
	struct meta2_raw_content_s raw_content;
	GSList* broken;

	test_dept_assert_false(check_meta2_chunk(NULL, &broken, &error));
	test_dept_assert_true(error);

	g_clear_error(&error);
	error = NULL;

	test_dept_assert_false(check_meta2_chunk(&raw_content, NULL, &error));
	test_dept_assert_true(error);
}

void
test_check_meta2_chunk()
{
        GError *error = NULL;
        struct meta2_raw_content_s* content_meta2;
        struct meta2_raw_chunk_s* chunk_meta2;
        GSList *mismatch = NULL;
        container_id_t container_id;
        chunk_id_t chunk_id;
	addr_info_t* rawx_addr = build_addr_info("127.0.0.1", 6523, &error);
	chunk_hash_t chunk_hash;

        test_dept_assert_true(hex2bin(CONTAINER_ID, container_id, sizeof(container_id_t), &error));
        content_meta2 = meta2_maintenance_create_content(container_id, CONTENT_SIZE, NB_CHUNK, 0, CONTENT_NAME, strlen(CONTENT_NAME));
        content_meta2->system_metadata = g_byte_array_append(g_byte_array_new(), CONTENT_SYSMETADATA, strlen(CONTENT_SYSMETADATA)+1);
	test_dept_assert_true(hex2bin(CHUNK_HASH, chunk_hash, sizeof(chunk_hash_t), &error));
        test_dept_assert_true(hex2bin(CHUNK_ID, chunk_id.id, sizeof(hash_sha256_t), &error));
	memcpy(&(chunk_id.addr), rawx_addr, sizeof(addr_info_t));
        chunk_meta2 = meta2_maintenance_create_chunk(&chunk_id, chunk_hash, CHUNK_POSITION, CHUNK_SIZE, 0);
        meta2_maintenance_add_chunk(content_meta2, chunk_meta2);

	test_dept_rawx_client_get_directory_data_set(fake_rawx_client_get_directory_data);

        //test_dept_assert_true(check_meta2_chunk(content_meta2, &mismatch, &error));
	if (!check_meta2_chunk(content_meta2, &mismatch, &error)) {
		ERROR("%s", error->message);
		return;
	}
        test_dept_assert_false(error);
        test_dept_assert_false(mismatch);
}
