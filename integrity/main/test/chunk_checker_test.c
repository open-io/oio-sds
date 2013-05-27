/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "chunk_checker.test"
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <test-dept.h>

#include <metautils.h>

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
