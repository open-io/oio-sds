#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "chunk_checker.test"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <test-dept.h>

#include <metautils/lib/metautils.h>
#include <rawx.h>

#include "chunk_check.h"
#include "broken_event.h"

#define VOLUME_ROOT "chunk_checker_test_fake_volume_root"
#define CHUNK_PATH VOLUME_ROOT"/AABBCC"
#define CHUNK_ATTR_PATH CHUNK_PATH".attr"
#define CONTAINER_ID "3A0495C6FF65615D43A078F578809AB8D8BB17A3F841861A6C51D0687EE5E1AF"
#define CHUNK_ID "C678F32385C07EB2A221ABA8C97F38DC46DDBA533121A34F81FDB96A0E4B8FCD"
#define CONTENT_NAME "content"
#define FILE_CONTENT "file file file"
#define CONTENT_SYSMETADATA "system metadata"

static gchar* str_chunk_hash;
static gchar* str_chunk_size;
static chunk_hash_t chunk_hash;
static gint64 chunk_size;

void
setup()
{
        GError *error = NULL;
	int fd;
	GChecksum *sum;
	gsize len = sizeof(chunk_hash_t);
	size_t bytes_written = 0;

	/* Init log4c */
	log4c_init();

	sum = g_checksum_new(G_CHECKSUM_MD5);
	g_checksum_update(sum, FILE_CONTENT, -1);

	str_chunk_hash = g_strdup(g_checksum_get_string(sum));
	g_checksum_get_digest(sum, chunk_hash, &len);

	g_checksum_free(sum);

	chunk_size = strlen(FILE_CONTENT);
	str_chunk_size = g_strdup_printf("%lli", chunk_size);

        struct chunk_textinfo_s chunk = {
                CHUNK_ID, 
                CONTENT_NAME,
                str_chunk_size,
                "2",
                str_chunk_hash,
                "metadata",
                CONTAINER_ID
        };

        struct content_textinfo_s content = {
                CONTAINER_ID,
                CONTENT_NAME,
                "4096",
                "3",
                "metadata",
                "system metadata"
        };

        /* Create fake volume root */
        mkdir(VOLUME_ROOT, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);

        /* Create fake chunk */
        fd = open(CHUNK_PATH, O_CREAT|O_WRONLY, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
	if (fd == -1) {
		ERROR("Failed to open file [%s] : %s", CHUNK_PATH, strerror(errno));
		return;
	}

	while (bytes_written < strlen(FILE_CONTENT)) {
		ssize_t rc;
		rc = write(fd, FILE_CONTENT+bytes_written, strlen(FILE_CONTENT)-bytes_written);
		if (rc == -1) {
			ERROR("Failed to write in chunk file [%s] (fd=%d) : %s", CHUNK_PATH, fd, strerror(errno));
			return;
		}
		else
			bytes_written += rc;
	}
	metautils_pclose(&fd);

        if (!set_rawx_info_in_attr(CHUNK_PATH, &error, &content, &chunk))
                ERROR(error->message);

	return;
}

void
teardown()
{
        /* Clean fake volume */
        unlink(CHUNK_PATH);
        unlink(CHUNK_ATTR_PATH);
        rmdir(VOLUME_ROOT);

	return;
}

void
test_check_chunk_integrity_args_null()
{
	GError *error = NULL;
	struct chunk_textinfo_s chunk;
	GSList *mismatch = NULL;

	test_dept_assert_false(check_chunk_integrity(NULL, &chunk, &mismatch, &error));
	test_dept_assert_true(error);

	g_clear_error(&error);
	error = NULL;

	test_dept_assert_false(check_chunk_integrity(CHUNK_PATH, NULL, &mismatch, &error));
	test_dept_assert_true(error);
}

void
test_check_chunk_integrity_path_unexistant()
{
	GError *error = NULL;
	struct chunk_textinfo_s chunk;
	GSList *mismatch = NULL;

	test_dept_assert_false(check_chunk_integrity("/path/to/nowhere", &chunk, &mismatch, &error));
	test_dept_assert_true(error);
}

void
test_check_chunk_integrity()
{
	GError *error = NULL;
	struct chunk_textinfo_s chunk;
	GSList *mismatch = NULL;

	chunk.hash = str_chunk_hash;
	chunk.size = str_chunk_size;

	test_dept_assert_true(check_chunk_integrity(CHUNK_PATH, &chunk, &mismatch, &error));
	test_dept_assert_false(error);
	test_dept_assert_false(mismatch);
}

void
test_check_chunk_integrity_bad_hash()
{
	GError *error = NULL;
	struct chunk_textinfo_s chunk;
	GSList *mismatch = NULL;
	struct broken_element_s* brk_el;

	chunk.container_id = CONTAINER_ID;
	chunk.path = CONTENT_NAME;
	chunk.id = CHUNK_ID;
	chunk.hash = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
	chunk.size = str_chunk_size;

	test_dept_assert_true(check_chunk_integrity(CHUNK_PATH, &chunk, &mismatch, &error));
	test_dept_assert_true(mismatch);
	test_dept_assert_equals_int(1, g_slist_length(mismatch));

	brk_el = g_slist_nth_data(mismatch, 0);

	test_dept_assert_true((brk_el->property == P_CHUNK_HASH));
	test_dept_assert_true((brk_el->reason == R_MISMATCH));

	g_slist_foreach(mismatch, broken_element_gfree, NULL);
	g_slist_free(mismatch);
}

void
test_check_chunk_integrity_bad_size()
{
	GError *error = NULL;
	struct chunk_textinfo_s chunk;
	GSList *mismatch = NULL;
	struct broken_element_s* brk_el;

	chunk.container_id = CONTAINER_ID;
	chunk.path = CONTENT_NAME;
	chunk.id = CHUNK_ID;
	chunk.hash = str_chunk_hash;
	chunk.size = "0";

	test_dept_assert_true(check_chunk_integrity(CHUNK_PATH, &chunk, &mismatch, &error));
	test_dept_assert_true(mismatch);
	test_dept_assert_equals_int(1, g_slist_length(mismatch));

	brk_el = g_slist_nth_data(mismatch, 0);

	test_dept_assert_true((brk_el->property == P_CHUNK_SIZE));
	test_dept_assert_true((brk_el->reason == R_MISMATCH));

	g_slist_foreach(mismatch, broken_element_gfree, NULL);
	g_slist_free(mismatch);
}

void
test_check_chunk_referencing_args_null()
{
	GError *error = NULL;
	struct content_textinfo_s content_text;
	struct chunk_textinfo_s chunk_text;
	struct meta2_raw_content_s content_meta2;
	GSList *mismatch = NULL;

	test_dept_assert_false(check_chunk_referencing(NULL, &chunk_text, &content_meta2, &mismatch, &error));
	test_dept_assert_true(error);

	g_clear_error(&error);
	error = NULL;

	test_dept_assert_false(check_chunk_referencing(&content_text, NULL, &content_meta2, &mismatch, &error));
	test_dept_assert_true(error);

	g_clear_error(&error);
	error = NULL;

	test_dept_assert_false(check_chunk_referencing(&content_text, &chunk_text, NULL, &mismatch, &error));
	test_dept_assert_true(error);
}

void
test_check_chunk_referencing()
{
	GError *error = NULL;
	struct content_textinfo_s content_text;
	struct chunk_textinfo_s chunk_text;
	struct meta2_raw_content_s* content_meta2;
	struct meta2_raw_chunk_s* chunk_meta2;
	GSList *mismatch = NULL;
	container_id_t container_id;
	chunk_id_t chunk_id;

	test_dept_assert_true(hex2bin(CONTAINER_ID, container_id, sizeof(container_id_t), &error));
	content_meta2 = meta2_maintenance_create_content(container_id, 4096, 3, 0, CONTENT_NAME, strlen(CONTENT_NAME));
	content_meta2->system_metadata = g_byte_array_append(g_byte_array_new(), CONTENT_SYSMETADATA, strlen(CONTENT_SYSMETADATA)+1);
	test_dept_assert_true(hex2bin(CHUNK_ID, chunk_id.id, sizeof(hash_sha256_t), &error));
	chunk_meta2 = meta2_maintenance_create_chunk(&chunk_id, chunk_hash, 0, chunk_size, 0);
	meta2_maintenance_add_chunk(content_meta2, chunk_meta2);

	content_text.container_id = CONTAINER_ID;
	content_text.path = CONTENT_NAME;
	content_text.size = "4096";
	content_text.chunk_nb = "3";
	content_text.metadata = "content metadata";
	content_text.system_metadata = CONTENT_SYSMETADATA;

	chunk_text.id = CHUNK_ID;
	chunk_text.path = CONTENT_NAME;
	chunk_text.size = str_chunk_size;
	chunk_text.position = "0";
	chunk_text.hash = str_chunk_hash;
	chunk_text.metadata = "chunk metadata";
	chunk_text.container_id = CONTAINER_ID;

	test_dept_assert_true(check_chunk_referencing(&content_text, &chunk_text, content_meta2, &mismatch, &error));
	test_dept_assert_false(error);
	test_dept_assert_false(mismatch);
}

void
test_check_chunk_referencing_meta2_empty_prop()
{
	GError *error = NULL;
	struct content_textinfo_s content_text;
	struct chunk_textinfo_s chunk_text;
	struct meta2_raw_content_s* content_meta2;
	struct meta2_raw_chunk_s* chunk_meta2;
	GSList *mismatch = NULL;
	container_id_t container_id;
	chunk_id_t chunk_id;
	gchar content_name[LIMIT_LENGTH_CONTENTPATH];
	chunk_hash_t hash;

	memset(container_id, 0, sizeof(container_id_t));
	memset(content_name, 0, sizeof(content_name));
	memset(&chunk_id, 0, sizeof(chunk_id_t));
	memset(hash, 0, sizeof(chunk_hash_t));

	content_meta2 = meta2_maintenance_create_content(container_id, 0, 0, 0, content_name, sizeof(content_name));
	chunk_meta2 = meta2_maintenance_create_chunk(&chunk_id, hash, 0, 0, 0);
	meta2_maintenance_add_chunk(content_meta2, chunk_meta2);

	content_text.container_id = CONTAINER_ID;
	content_text.path = CONTENT_NAME;
	content_text.size = "4096";
	content_text.chunk_nb = "3";
	content_text.metadata = "content metadata";
	content_text.system_metadata = "system metadata";

	chunk_text.id = CHUNK_ID;
	chunk_text.path = CONTENT_NAME;
	chunk_text.size = str_chunk_size;
	chunk_text.position = "1";
	chunk_text.hash = str_chunk_hash;
	chunk_text.metadata = "chunk metadata";
	chunk_text.container_id = CONTAINER_ID;

	test_dept_assert_true(check_chunk_referencing(&content_text, &chunk_text, content_meta2, &mismatch, &error));
	test_dept_assert_false(error);
	test_dept_assert_true(mismatch);
	test_dept_assert_equals_int(6, g_slist_length(mismatch));
}

void
test_check_chunk_referencing_chunk_empty_attr()
{
	GError *error = NULL;
	struct content_textinfo_s content_text;
	struct chunk_textinfo_s chunk_text;
	struct meta2_raw_content_s* content_meta2;
	struct meta2_raw_chunk_s* chunk_meta2;
	GSList *mismatch = NULL;
	container_id_t container_id;
	chunk_id_t chunk_id;
	
	memset(&content_text, 0, sizeof(struct content_textinfo_s));
	memset(&chunk_text, 0, sizeof(struct chunk_textinfo_s));
	
	test_dept_assert_true(hex2bin(CONTAINER_ID, container_id, sizeof(container_id_t), &error));
	content_meta2 = meta2_maintenance_create_content(container_id, 4096, 3, 0, CONTENT_NAME, strlen(CONTENT_NAME));
	content_meta2->system_metadata = g_byte_array_append(g_byte_array_new(), CONTENT_SYSMETADATA, strlen(CONTENT_SYSMETADATA)+1);
	test_dept_assert_true(hex2bin(CHUNK_ID, chunk_id.id, sizeof(hash_sha256_t), &error));
	chunk_meta2 = meta2_maintenance_create_chunk(&chunk_id, chunk_hash, 0, chunk_size, 1);
	meta2_maintenance_add_chunk(content_meta2, chunk_meta2);

	test_dept_assert_true(check_chunk_referencing(&content_text, &chunk_text, content_meta2, &mismatch, &error));
	test_dept_assert_false(error);
	test_dept_assert_true(mismatch);
	test_dept_assert_equals_int(6, g_slist_length(mismatch));
}

void
test_check_chunk_referencing_chunk_position_zero_empty_attr()
{
	GError *error = NULL;
	struct content_textinfo_s content_text;
	struct chunk_textinfo_s chunk_text;
	struct meta2_raw_content_s* content_meta2;
	struct meta2_raw_chunk_s* chunk_meta2;
	GSList *mismatch = NULL;
	container_id_t container_id;
	chunk_id_t chunk_id;

	memset(&content_text, 0, sizeof(struct content_textinfo_s));
	memset(&chunk_text, 0, sizeof(struct chunk_textinfo_s));

	chunk_text.position = "0";

	test_dept_assert_true(hex2bin(CONTAINER_ID, container_id, sizeof(container_id_t), &error));
	content_meta2 = meta2_maintenance_create_content(container_id, 4096, 3, 0, CONTENT_NAME, strlen(CONTENT_NAME));
	content_meta2->system_metadata = g_byte_array_append(g_byte_array_new(), CONTENT_SYSMETADATA, strlen(CONTENT_SYSMETADATA)+1);
	test_dept_assert_true(hex2bin(CHUNK_ID, chunk_id.id, sizeof(hash_sha256_t), &error));
	chunk_meta2 = meta2_maintenance_create_chunk(&chunk_id, chunk_hash, 0, chunk_size, 3);
	meta2_maintenance_add_chunk(content_meta2, chunk_meta2);

	test_dept_assert_true(check_chunk_referencing(&content_text, &chunk_text, content_meta2, &mismatch, &error));
	test_dept_assert_false(error);
	test_dept_assert_true(mismatch);
	test_dept_assert_equals_int(8, g_slist_length(mismatch));
}
