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

#include "chunk_checker.h"


void
setup()
{
	log4c_init();

	return;
}

void
teardown()
{
	log4c_fini();

	return;
}

void
test_check_chunk_args_null()
{
	GError *error = NULL;

        test_dept_assert_false(check_chunk(NULL, NULL, &error));
        test_dept_assert_true(error);
}

void
test_check_chunk_path_unexistant()
{
	GError *error = NULL;

	test_dept_assert_false(check_chunk("/path/to/nowhere", NULL, &error));
	test_dept_assert_true(error);
}
