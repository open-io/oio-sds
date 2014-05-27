#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <glib.h>
#include <errno.h>

#include <test-dept.h>

#include <metautils/lib/metautils.h>

#include "volume_scanner.h"

static gboolean
fake_scanner_callback(const gchar* file_path, void* data, GError **error)
{
	(void) error;
	GSList** list_file = (GSList**)data;

	*list_file = g_slist_prepend(*list_file, g_strdup(file_path));

	return TRUE;
}

void
setup()
{
	/* Init log4c */
	log4c_init();

	/* Create fake file tree */
	mkdir("volume_scanner_test_fake_file_tree", S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
	mkdir("volume_scanner_test_fake_file_tree/aa", S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
	mkdir("volume_scanner_test_fake_file_tree/aa/bb", S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);
	mkdir("volume_scanner_test_fake_file_tree/aa/cc", S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH);

	close(open("volume_scanner_test_fake_file_tree/aa/bb/AABBCC", O_CREAT, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH));
	close(open("volume_scanner_test_fake_file_tree/aa/cc/AACCDD", O_CREAT, S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH|S_IXOTH));

	return;
}

void
teardown()
{
	/* Destroy fake file tree */
	unlink("volume_scanner_test_fake_file_tree/aa/bb/AABBCC");
	unlink("volume_scanner_test_fake_file_tree/aa/cc/AACCDD");
	rmdir("volume_scanner_test_fake_file_tree/aa/cc");
	rmdir("volume_scanner_test_fake_file_tree/aa/bb");
	rmdir("volume_scanner_test_fake_file_tree/aa");
	rmdir("volume_scanner_test_fake_file_tree");

	/* Shutdown log4c */
	log4c_fini();

	return;
}

void
test_files_all_match()
{
	GSList *list_file = NULL;
	struct volume_scanning_info_s scanning_info;

	scanning_info.volume_path = "volume_scanner_test_fake_file_tree";
	scanning_info.matching_glob = "*";
	scanning_info.callback = fake_scanner_callback;
	scanning_info.callback_data = &list_file;
	scanning_info.sleep_time = 1;

	scan_volume(&scanning_info);

	test_dept_assert_equals_int((int)g_slist_length(list_file), 2);
}

void
test_files_none_match()
{
	GSList *list_file = NULL;
	struct volume_scanning_info_s scanning_info;

	scanning_info.volume_path = "volume_scanner_test_fake_file_tree";
	scanning_info.matching_glob = "*.fake";
	scanning_info.callback = fake_scanner_callback;
	scanning_info.callback_data = &list_file;
	scanning_info.sleep_time = 1;

	scan_volume(&scanning_info);

	test_dept_assert_equals_int((int)g_slist_length(list_file), 0);
}
