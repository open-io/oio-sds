#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>

#include <test-dept.h>
#include <metautils/lib/metautils.h>
#include <rawx.h>

#include "../lib/chunk_db.h"
#include "chunk_crawler.h"


#define VOLUME_ROOT "chunk_crawler_test_fake_volume_root"
#define CONTENT_DB VOLUME_ROOT"/"CONTENT_DB_NAME
#define CONTAINER_DB VOLUME_ROOT"/"CONTAINER_DB_NAME
#define CHUNK_PATH VOLUME_ROOT"/AABBCC"
#define CHUNK_ATTR_PATH CHUNK_PATH".attr"
#define CONTAINER_ID "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
#define CONTENT_NAME "content"

void
setup()
{
	GError *error = NULL;

	struct chunk_textinfo_s chunk = {
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 
		CONTENT_NAME,
		"1024",
		"2",
		"AEBD15498AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
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

	/* Init log4c */
	log4c_init();

	/* Create fake volume root */
	mkdir(VOLUME_ROOT, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);

	/* Create fake chunk */
	close(open(CHUNK_PATH,
		O_CREAT, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH));

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
	unlink(CONTENT_DB);
	unlink(CONTAINER_DB);
	rmdir(VOLUME_ROOT);

	return;
}

void
test_args_null()
{
	GError *error = NULL;

        test_dept_assert_false(save_chunk_to_db(NULL, VOLUME_ROOT, &error));
        test_dept_assert_true(error);

	g_clear_error(&error);
	error = NULL;

        test_dept_assert_false(save_chunk_to_db(CHUNK_PATH, NULL, &error));
        test_dept_assert_true(error);
}

void
test_arg_chunk_path_unexistant()
{
	GError *error = NULL;

	test_dept_assert_false(save_chunk_to_db("/path/to/nowhere", VOLUME_ROOT, &error));
	test_dept_assert_true(error);
}

void
test_arg_volume_root_unexistant()
{
	GError *error = NULL;

	test_dept_assert_false(save_chunk_to_db(CHUNK_PATH, "/path/to/nowhere", &error));
	test_dept_assert_true(error);
}

void
test_chunk_added_to_content_db()
{
	GError *error = NULL;
	GSList* list_chunk;

	test_dept_assert_true(save_chunk_to_db(CHUNK_PATH, VOLUME_ROOT, &error));
	test_dept_assert_true(get_content_chunks(VOLUME_ROOT, CONTENT_NAME, &list_chunk, &error));
	test_dept_assert_true(list_chunk);
	test_dept_assert_equals_string(((char*)g_slist_nth(list_chunk, 0)->data), CHUNK_PATH);

	return;
}

void
test_chunk_added_to_container_db()
{
	GError *error = NULL;
	GSList* list_chunk;

	test_dept_assert_true(save_chunk_to_db(CHUNK_PATH, VOLUME_ROOT, &error));
	test_dept_assert_true(get_container_chunks(VOLUME_ROOT, CONTAINER_ID, &list_chunk, &error));
	test_dept_assert_true(list_chunk);
	test_dept_assert_equals_string(((char*)g_slist_nth(list_chunk, 0)->data), CHUNK_PATH);

	return;
}
