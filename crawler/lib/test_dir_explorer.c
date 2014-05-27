#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "crawler.test"
#endif

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <metautils/lib/metautils.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "dir_explorer.h"

static gchar *global_base = NULL;

static guint
_next_id(void)
{
	static guint id = 0;
	return id ++;
}

struct citizen_s
{
	const gchar *dirname;
	const gchar *basename;
	int mode;
};

static void
_erase(const gchar *dn)
{
	const gchar *bn;
	GError *err = NULL;
	GDir *dir = g_dir_open(dn, 0, &err);
	if (dir == NULL) {
		g_warning("g_dir_open(%s) failed : (%d) %s", dn, errno, strerror(errno));
		g_clear_error(&err);
		return;
	}
	while (NULL != (bn = g_dir_read_name(dir))) {
		gchar *full = g_strconcat(dn, G_DIR_SEPARATOR_S, bn, NULL);
		(void) g_chmod(full, 0700);
		if (g_file_test(full, G_FILE_TEST_IS_DIR))
			_erase(full);
		else
			g_unlink(full);
		g_free(full);
	}
	g_dir_close(dir);
	g_rmdir(dn);
}


static void
_population_create(const gchar *basedir, struct citizen_s *population)
{
	for (; population->dirname ;++population) {
		gchar *dn = g_strconcat(basedir, G_DIR_SEPARATOR_S,
				population->dirname, NULL);
		if (0 != g_mkdir_with_parents(dn, 0700))
			g_error("Try error: mkdir(%s) : (%d) %s", dn, errno, strerror(errno));
		if (population->basename && population->basename[0]) {
			gchar *full = g_strconcat(dn, G_DIR_SEPARATOR_S,
					population->basename, NULL);
			int fd = open(full, O_CREAT|O_TRUNC|O_SYNC, 0600);
			if (fd < 0)
				g_error("Try error: open(%s) : (%d) %s", full, errno, strerror(errno));
			metautils_pclose(&fd);
			g_free(full);
		}
		g_free(dn);
	}
}

static void
_population_apply_perms(const gchar *basedir, struct citizen_s *population)
{
	for (; population->dirname ;++population) {
		gchar *full;
		if (population->basename && population->basename[0])
			full = g_strconcat(basedir, G_DIR_SEPARATOR_S,
					population->dirname, G_DIR_SEPARATOR_S,
					population->basename, NULL);
		else
			full = g_strconcat(basedir, G_DIR_SEPARATOR_S,
				population->dirname, NULL);
		(void) chmod(full, population->mode);
		g_free(full);
	}
}

static void
_populate(const gchar *basedir, struct citizen_s *population)
{
	g_assert(population != NULL);
	_population_create(basedir, population);
	_population_apply_perms(basedir, population);
}

static void
_crawl(gchar *basedir)
{
	dir_explorer_t explorer;
	GError *err;

	err = NULL;
	memset(&explorer, 0, sizeof(explorer));

	err = dir_explore(basedir, &explorer);
	g_assert_no_error(err);
	for (;;) {
		gchar *path = dir_next_file(&explorer, NULL);
		if (!path)
			break;
		g_debug("PATH = %s", path);
		g_free(path);
	}
	dir_explorer_clean(&explorer);
}

//------------------------------------------------------------------------------

static void
_test_not_found(void)
{
	gchar *basedir = g_strdup_printf("%s/try-%u", global_base, _next_id());
	dir_explorer_t explorer;
	GError *err;

	memset(&explorer, 0, sizeof(explorer));
	err = dir_explore(basedir, &explorer);
	g_assert(err != NULL);
	dir_explorer_clean(&explorer);
	g_free(basedir);
}

static void
_test_empty(void)
{
	gchar *basedir = g_strdup_printf("%s/try-%u", global_base, _next_id());
	if (0 != g_mkdir_with_parents(basedir, 0700))
		g_error("Try failure [%s] : (%d) %s", basedir, errno, strerror(errno));
	_crawl(basedir);
	g_free(basedir);
}

static void
_test_simple(void)
{
	static struct citizen_s citizens[] = {
		{"/", "", 0400},
		{"/", "plop", 0600},
		{"/", "plip", 0600},
		{"/", "plup", 0600},
		{"/", "plap", 0600},
		{NULL, NULL, 0}
	};
	gchar *basedir = g_strdup_printf("%s/try-%u", global_base, _next_id());
	if (0 != g_mkdir_with_parents(basedir, 0700))
		g_error("Try failure [%s] : (%d) %s", basedir, errno, strerror(errno));
	_populate(basedir, citizens);
	_crawl(basedir);
	g_free(basedir);
}


int
main(int argc, char **argv)
{
	if (!g_thread_supported())
		g_thread_init(NULL);
	g_set_prgname(argv[0]);
	g_log_set_default_handler(logger_stderr, NULL);
	logger_init_level(GRID_LOGLVL_TRACE2);
	g_test_init (&argc, &argv, NULL);

	global_base = g_strdup_printf("/tmp/crawler-test-%d-%ld", getpid(), time(0));
	if (0 != g_mkdir_with_parents(global_base, 0700))
		g_error("Preparation failure [%s] : (%d) %s", global_base, errno, strerror(errno));

	g_test_add_func("/crawler/dir_explorer/not_found", _test_not_found);
	g_test_add_func("/crawler/dir_explorer/empty", _test_empty);
	g_test_add_func("/crawler/dir_explorer/simple", _test_simple);
	int rc = g_test_run();

	_erase(global_base);
	g_free(global_base);
	global_base = NULL;

	return rc;
}

