/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sqlite3.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo_variables.h>

#include "sqliterepo.h"
#include "hash.h"
#include "cache.h"
#include "election.h"
#include "version.h"
#include "sqlite_utils.h"
#include "internals.h"
#include "restoration.h"
#include "sqlx_remote.h"


#define GSTR_APPEND_SEP(S) do { \
	if ((S)->str[(S)->len-1]!=G_DIR_SEPARATOR) \
			g_string_append_c((S), G_DIR_SEPARATOR); \
} while (0)

static gboolean
election_manager_configured(const struct election_manager_s *em)
{
	return em && (ELECTION_MODE_NONE != election_manager_get_mode (em));
}

static void
_close_handle(sqlite3 **pdb)
{
	if (unlikely(NULL == pdb))
		return;
	if (NULL != *pdb) {
		(void) sqlite3_close(*pdb);
		*pdb = NULL;
	}
}

static gchar*
_compute_path_hash(sqlx_repository_t *repo, const hashstr_t *hn, const gchar *t)
{
	guint w, d, i = 0;
	gsize nlen;
	GString *gstr;
	const gchar *n;

	n = hashstr_str(hn);
	nlen = hashstr_len(hn);

	/* This shortcut help plugging test code. the test
	 * program is then free to define a <sqlx_file_locator_f> that generates
	 * an absolute path, or a special name (for sqlite3, e.g. ":memory:").
	 * This is UGLY, I admit it without any torture. Changing it would (e.g.)
	 * consist in systematically providing the <locator> instead of the
	 * volume's <basedir> and the repository init, and then expecting the
	 * <locator> to return the WHOLE path instead of just the filenames. */
	if (*n == '/' || *n == ':')
		return g_strdup (n);

	gstr = g_string_sized_new(256);
	g_string_append(gstr, repo->basedir);

	for (d=0; d<repo->hash_depth ;d++) {

		if ((d+1) * repo->hash_width > nlen)
			goto label_end;

		GSTR_APPEND_SEP(gstr);
		for (w=0; w<repo->hash_width ;w++) {
			register gchar c;
			if (!(c = n[i++]))
				goto label_end;
			g_string_append_c(gstr, c);
		}
		GSTR_APPEND_SEP(gstr);
	}

label_end:
	GSTR_APPEND_SEP(gstr);
	g_string_append_len(gstr, n, nlen);
	if (t && *t) {
		g_string_append_c(gstr, '.');
		g_string_append(gstr, t);
	}
	return g_string_free(gstr, FALSE);
}

/* ------------------------------------------------------------------------- */

static void
__delete_base(struct sqlx_sqlite3_s *sq3)
{
	if (!sq3->path_inline[0]) {
		GRID_WARN("DELETE disabled [%s][%s]", sq3->name.base, sq3->name.type);
		return;
	}

	if (!unlink(sq3->path_inline))
		GRID_DEBUG("DELETE done [%s][%s] (%s)", sq3->name.base,
			sq3->name.type, sq3->path_inline);
	else
		GRID_WARN("DELETE failed [%s][%s] (%s): (%d) %s",
				sq3->name.base, sq3->name.type, sq3->path_inline,
				errno, strerror(errno));
	sq3->deleted = 0;
}

static void
__rename_base(struct sqlx_sqlite3_s *sq3, const gchar *dst)
{
	EXTRA_ASSERT(sq3->path_inline[0] != '\0');
	EXTRA_ASSERT(dst != NULL && dst[0] != '\0');
	if (rename(sq3->path_inline, dst) < 0) {
		GRID_WARN("Failed to rename %s to %s: (%d) %s",
				sq3->path_inline, dst, errno, strerror(errno));
	} else {
		GRID_DEBUG("[%s][%s] base renamed to %s",
				sq3->name.base, sq3->name.type, dst);
	}
}

static void
__close_base(struct sqlx_sqlite3_s *sq3)
{
	if (!sq3) {
		GRID_DEBUG("Closing a NULL db handle");
		return;
	}

	GRID_TRACE2("DB being closed [%s][%s]", sq3->name.base,
			sq3->name.type);

	/* send a vacuum */
	if (sq3->repo && sq3->repo->flag_autovacuum)
		sqlx_exec(sq3->db, "VACUUM");

	sqlx_repository_call_close_callback(sq3);

	if (sq3->deleted || sq3->corrupted) {
		if (sq3->repo->election_manager) {
			NAME2CONST(n0, sq3->name);
			GError *err = election_exit(sq3->repo->election_manager, &n0);
			if (err) {
				GRID_WARN("Failed to exit election [%s][%s]: (%d) %s",
						sq3->name.base, sq3->name.type,
						err->code, err->message);
				g_clear_error(&err);
			} else {
				GRID_TRACE("exit election succeeded [%s][%s]",
						sq3->name.base, sq3->name.type);
			}
		}

		if (sq3->deleted) {
			__delete_base(sq3);
		} else if (sq3->corrupted) {
			gchar dst[sizeof(sq3->path_inline) + sizeof(SQLX_CORRUPT_SUFFIX)];
			char *suffix = stpcpy(dst, sq3->path_inline);
			strcpy(suffix, SQLX_CORRUPT_SUFFIX);
			GRID_ERROR("Renaming corrupted base [%s][%s] to %s",
					sq3->name.base, sq3->name.type, dst);
			__rename_base(sq3, dst);
			sq3->corrupted = 0;
		}
	}

	if (sq3->db)
		_close_handle(&(sq3->db));

	/* Clean the structure */
	sq3->path_inline[0] = 0;
	if (sq3->admin)
		g_tree_destroy(sq3->admin);
	sq3->bd = -1;
	SLICE_FREE(struct sqlx_sqlite3_s, sq3);
}

static int
_schema_apply (sqlite3 *db, const char *schema)
{
	int rc = sqlx_exec (db, "CREATE TABLE admin ("
			"k TEXT PRIMARY KEY NOT NULL, v BLOB DEFAULT NULL)");
	return (rc != SQLITE_OK) ? rc : sqlx_exec (db, schema);
}

static GError*
_schema_test (const char *schema)
{
	GError *error = NULL;
	sqlite3 *db = NULL;
	int rc = sqlite3_open_v2(":memory:", &db, SQLITE_OPEN_NOMUTEX
			|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL);
	if (rc != SQLITE_OK)
		error = NEWERROR(rc, "SQL error (open): (%d) %s",
				rc, sqlite3_errmsg(db));
	else if (SQLITE_OK != (rc = _schema_apply (db, schema)))
		error = NEWERROR(rc, "SQL error (schema): (%d) %s",
				rc, sqlite3_errmsg(db));
	_close_handle(&db);
	return error;
}

static GError*
_schema_get (sqlx_repository_t *repo, const char *type, const char **res)
{
	gchar *schema = NULL;

	/* XXX(jfs): ugly quirk to quickly manage (in one place and without
	   excess of abstractions) 2 kinds of services with opposed behaviors.
	   On one side, we have meta2 where all the meta2[.*] services MUST have
	   exactly the same schema, and on the other side the sqlx[.*] that
	   might all have different schemas, and maybe no specific schema at all. */
	if (!strcmp(type, NAME_SRVTYPE_SQLX) ||
			g_str_has_prefix (type, NAME_SRVTYPE_SQLX".")) {
		if (!(schema = g_tree_lookup (repo->schemas, type)))
			schema = g_tree_lookup (repo->schemas, NAME_SRVTYPE_SQLX);
		if (!schema)
			schema = "";
	} else {
		gchar *realtype = g_strdup (type);
		gchar *dot = strchr(realtype, '.');
		if (dot) *dot = '\0';
		schema = g_tree_lookup(repo->schemas, realtype);
		g_free (realtype);
	}

	if (!schema)
		return NEWERROR(CODE_SRVTYPE_NOTMANAGED, "Type [%s] not managed", type);
	if (res)
		*res = schema;
	return NULL;
}

static gboolean
_schema_has (sqlite3 *db)
{
	int rc, count = 0;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug (rc, db,
			"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'",
			-1, &stmt, NULL);
	while (SQLITE_ROW == (rc = sqlite3_step(stmt)))
		count += sqlite3_column_int (stmt, 0);
	sqlite3_finalize_debug (rc, stmt);

	return count > 0;
}

static void
_default_locator (gpointer ignored, const struct sqlx_name_s *n, GString *result)
{
	SQLXNAME_CHECK(n);
	EXTRA_ASSERT(result != NULL);
	(void) ignored;

	g_string_append (result, n->base);
	g_string_append_c (result, '.');
	g_string_append (result, n->type);
}

/* ------------------------------------------------------------------------- */

GError *
sqlx_repository_init(const gchar *vol, const struct sqlx_repo_config_s *cfg,
		sqlx_repository_t **result)
{
	gchar tmpdir[LIMIT_LENGTH_VOLUMENAME+8] = {0};
	struct stat s;
	sqlx_repository_t *repo;

	g_assert_nonnull(vol);
	g_assert_nonnull(cfg);
	g_assert_nonnull(result);

	(void) sqlite3_initialize();

	if (!sqlite3_threadsafe())
		return NEWERROR(0, "SQLite not in safe mode");

	if (cfg->flags & SQLX_REPO_NOCACHE) {
		/* if there are several connections on the same base, we will use a
		   shared cache that wil prevent us of too many I/O operations. */
		if (SQLITE_OK != sqlite3_enable_shared_cache(1))
			GRID_NOTICE("SQLite3 not in SHAREDCACHE mode");
	}

	EXTRA_ASSERT(vol != NULL);
	EXTRA_ASSERT(*vol != '\0');
	EXTRA_ASSERT(result != NULL);

	/* Check the rights on the volume */
	if (-1 == stat(vol, &s))
		return NEWERROR(errno, "Invalid directory : %s", strerror(errno));

	if (!S_ISDIR(s.st_mode))
		return NEWERROR(errno, "Invalid directory : not a directory");

	int ok_usr = ((s.st_mode & S_IRWXU) == S_IRWXU);
	int ok_grp = ((s.st_mode & S_IRWXG) == S_IRWXG);
	int ok_oth = ((s.st_mode & S_IRWXO) == S_IRWXO);
	int ok = !getuid() /* especially for root */
		||  ok_oth
		|| (ok_grp && getgid() == s.st_gid)
		|| (ok_usr && getuid() == s.st_uid);

	if (!ok)
		return NEWERROR(errno, "Invalid directory : insufficient permissions");

	/* Create the directory used by dump/restore functions */
	g_snprintf(tmpdir, sizeof(tmpdir), "%s/tmp", vol);
	g_mkdir(tmpdir, 0755);

	repo = g_malloc0(sizeof(struct sqlx_repository_s));
	g_strlcpy(repo->basedir, vol, sizeof(repo->basedir)-1);
	repo->hash_depth = 1;
	repo->hash_width = 3;

	repo->schemas = g_tree_new_full(metautils_strcmp3, NULL, g_free, g_free);

	repo->flag_autovacuum = BOOL(cfg->flags & SQLX_REPO_VACUUM);
	repo->flag_delete_on = BOOL(cfg->flags & SQLX_REPO_DELETEON);

	if (!(cfg->flags & SQLX_REPO_NOCACHE)) {
		repo->cache = sqlx_cache_init();
		sqlx_cache_set_close_hook(repo->cache,
				(sqlx_cache_close_hook)__close_base);
	}

	repo->sync_mode_solo = cfg->sync_solo;
	repo->sync_mode_repli = cfg->sync_repli;

	repo->locator = _default_locator;
	repo->locator_data = NULL;

	repo->running = BOOL(TRUE);
	*result = repo;
	return NULL;
}

gboolean
sqlx_repository_running(sqlx_repository_t *repo)
{
	return repo != NULL && repo->running;
}

void
sqlx_repository_stop(sqlx_repository_t *repo)
{
	if (!repo)
		return ;
	repo->running = FALSE;
}

void
sqlx_repository_clean(sqlx_repository_t *repo)
{
	if (!repo)
		return;

	sqlx_repository_stop(repo);

	if (repo->election_manager)
		repo->election_manager = NULL;

	if (repo->cache) {
		sqlx_cache_expire_all(repo->cache);
		sqlx_cache_clean(repo->cache);
		repo->cache = NULL;
	}

	if (repo->schemas)
		g_tree_destroy (repo->schemas);

	memset(repo, 0, sizeof(*repo));
	g_free(repo);

	int rc;
	do {
		rc = sqlite3_release_memory(1024 * 1024);
	} while (rc > 0);
}

void
sqlx_repository_configure_hash(sqlx_repository_t *repo, guint w, guint d)
{
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(repo->running);
	EXTRA_ASSERT(4 >= (w * d));

	repo->hash_depth = d;
	repo->hash_width = w;
	GRID_DEBUG("Repository path hash configured: depth=%u width=%u",
			repo->hash_depth, repo->hash_width);
}

GError*
sqlx_repository_configure_type(sqlx_repository_t *repo,
		const char *type, const char *schema)
{
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(repo->running);
	EXTRA_ASSERT(type != NULL);
	EXTRA_ASSERT(schema != NULL);

	GError *error = NULL;
	if (NULL != (error = _schema_test(schema)))
		return error;

	g_tree_replace (repo->schemas, g_strdup (type), g_strdup (schema));
	GRID_INFO("Schema configured for type [%s]", type);
	return NULL;
}

void
sqlx_repository_configure_close_callback(sqlx_repository_t *repo,
		sqlx_repo_close_hook cb, gpointer cb_data)
{
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(repo->running);
	EXTRA_ASSERT(cb != NULL);

	repo->close_callback = cb;
	repo->close_callback_data = cb_data;
}

void
sqlx_repository_call_close_callback(struct sqlx_sqlite3_s *sq3)
{
	if (sq3->repo != NULL && sq3->repo->close_callback != NULL) {
		sq3->repo->close_callback(sq3, sq3->deleted,
				sq3->repo->close_callback_data);
	}
}

void
sqlx_repository_configure_open_callback(sqlx_repository_t *repo,
		sqlx_repo_open_hook cb, gpointer cb_data)
{
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(repo->running);
	EXTRA_ASSERT(cb != NULL);

	repo->open_callback = cb;
	repo->open_callback_data = cb_data;
}

void
sqlx_repository_configure_change_callback(sqlx_repository_t *repo,
		sqlx_repo_change_hook cb, gpointer cb_data)
{
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(repo->running);
	EXTRA_ASSERT(cb != NULL);

	repo->change_callback = cb;
	repo->change_callback_data = cb_data;
}

void
sqlx_repository_call_change_callback(struct sqlx_sqlite3_s *sq3)
{
	if (NULL == sq3 || NULL == sq3->repo)
		return;
	if (!sq3->repo->running)
		return;
	if (sq3->repo->change_callback)
		sq3->repo->change_callback(sq3, sq3->repo->change_callback_data);
}

void
sqlx_repository_set_locator(struct sqlx_repository_s *repo,
		sqlx_file_locator_f locator, gpointer locator_data)
{
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(locator != NULL);
	EXTRA_ASSERT(repo->running);
	repo->locator = locator;
	repo->locator_data = locator_data;
}

gboolean
sqlx_repository_replication_configured(const struct sqlx_repository_s *r)
{
	EXTRA_ASSERT(r != NULL);
	return election_manager_configured(r->election_manager);
}

void
sqlx_repository_set_elections(sqlx_repository_t *repo,
		struct election_manager_s *manager)
{
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(repo->election_manager == NULL);
	EXTRA_ASSERT(manager != NULL);
	if (repo)
		repo->election_manager = manager;
}

struct election_manager_s*
sqlx_repository_get_elections_manager(struct sqlx_repository_s *r)
{
	EXTRA_ASSERT(r != NULL);
	return r ? r->election_manager : NULL;
}

struct sqlx_cache_s *
sqlx_repository_get_cache(struct sqlx_repository_s *r)
{
	EXTRA_ASSERT(r != NULL);
	return r->cache;
}

const gchar*
sqlx_repository_get_local_addr(struct sqlx_repository_s *repo)
{
	struct election_manager_s* em = sqlx_repository_get_elections_manager(repo);
	if (em)
		return election_manager_get_local (em);
	return NULL;
}

/* ------------------------------------------------------------------------- */

struct open_args_s
{
	struct sqlx_repository_s *repo;
	struct sqlx_name_s name;
	const char *schema;
	hashstr_t *realname;
	gchar *realpath;
	gint64 deadline;

	gboolean create : 1;
	gboolean no_refcheck : 1;
	gboolean urgent : 1;
	gboolean is_replicated : 1;
};

static GError*
__create_directory(gchar *path)
{
	GError *error = NULL;
	gchar *start, *s;

	/* find the last SEP */
	start = path;
	s = path + strlen(path) - 1;
	for (; s >= start && *s != G_DIR_SEPARATOR ;s--);

	if (s > start && *s == G_DIR_SEPARATOR) {
		*s = '\0';
		if (0 != g_mkdir_with_parents(start, 0750))
			error = NEWERROR(errno, "mkdir(%s) error : %d (%s)",
					start, errno, strerror(errno));
		else {
			GRID_TRACE("mkdir(%s)", start);
		}
		*s = G_DIR_SEPARATOR;
	}

	return error;
}

static GError *
_open_fill_args(struct open_args_s *args, struct sqlx_repository_s *repo,
		const struct sqlx_name_s *n)
{
	EXTRA_ASSERT(args != NULL);
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(repo->locator != NULL);
	SQLXNAME_CHECK(n);

	/* A shard number should always have a strictly-positive sequence
	 * number. And this is enforced since the sharding of containers,
	 * to detect more (unacceptable) errors at runtime. */
	EXTRA_ASSERT(!g_str_has_suffix(n->base, ".0"));

	args->repo = repo;
	args->name.type = n->type;
	args->name.base = n->base;
	args->name.ns = n->ns;

	GString *fn = g_string_sized_new(256);
	repo->locator(repo->locator_data, n, fn);
	args->realname = hashstr_create_from_gstring(fn);
	args->realpath = _compute_path_hash(repo, args->realname, NULL);
	g_string_free(fn, TRUE);

	return _schema_get(repo, args->name.type, &(args->schema));
}

static void
_open_clean_args(struct open_args_s *args)
{
	if (args->realname)
		g_free(args->realname);
	if (args->realpath)
		g_free(args->realpath);
}

static const gchar *
_get_pragma_sync(register const int mode)
{
	switch (mode) {
		case SQLX_SYNC_OFF:
			return "PRAGMA synchronous = OFF";
		case SQLX_SYNC_NORMAL:
			return "PRAGMA synchronous = NORMAL";
		case SQLX_SYNC_FULL:
			return "PRAGMA synchronous = FULL";
		default:
			return "PRAGMA synchronous = NORMAL";
	}
}

/* XXX this should not be called during a transaction */
void
sqlx_admin_reload(struct sqlx_sqlite3_s *sq3)
{
	if (sq3->admin)
		g_tree_destroy(sq3->admin);
	sq3->admin = g_tree_new_full(metautils_strcmp3, NULL, g_free, g_free);

	sqlx_admin_load (sq3);
	sqlx_admin_ensure_versions (sq3);
	sqlx_admin_save_lazy_tnx (sq3);
	sq3->admin_dirty = 0;
	GRID_TRACE("Loaded %u ADMIN from [%s.%s]", g_tree_nnodes(sq3->admin),
			sq3->name.base, sq3->name.type);
}

static GError*
__open_not_cached(struct open_args_s *args, struct sqlx_sqlite3_s **result)
{
	GError *error = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	sqlite3 *handle = NULL;
	guint attempts = 2;
	gint rc, flags = 0;

retry:
	flags |= SQLITE_OPEN_NOMUTEX;
	flags |= SQLITE_OPEN_PRIVATECACHE;
	flags |= SQLITE_OPEN_READWRITE;
	if (args->create)
		flags |= SQLITE_OPEN_CREATE;
	handle = NULL;

	if (args->deadline && oio_ext_monotonic_time() > args->deadline)
		return BUSY("Deadline reached [%s]", args->realpath);

	switch (rc = sqlite3_open_v2(args->realpath, &handle, flags, NULL)) {
		case SQLITE_OK:
		case SQLITE_DONE:
			GRID_TRACE2("Open succeeded [%s]", args->realpath);
			break;
		case SQLITE_NOTFOUND:
		case SQLITE_CANTOPEN:
			GRID_DEBUG("Open soft error [%s]: (%d) %s", args->realpath,
					rc, sqlite_strerror(rc));
			if (attempts-- && args->create) {
				_close_handle(&handle);
				if (!(error = __create_directory(args->realpath))) {
					GRID_TRACE("Directory created, retrying open [%s]", args->realpath);
					goto retry;
				}
				GRID_DEBUG("DB creation error on [%s]: (%d) %s",
						args->realpath, error->code, error->message);
			} else {
			// FALLTHROUGH
		default:
				_close_handle(&handle);
				GRID_DEBUG("Open strong error [%s]: (%d) %s",
						args->realpath, rc, sqlite_strerror(rc));
				error = NEWERROR(CODE_CONTAINER_NOTFOUND, "sqlite3_open error:"
						" (errno=%d %s) (rc=%d) %s", errno, strerror(errno),
						rc, sqlite_strerror(rc));
			}
			return error;
	}

	sqlite3_commit_hook(handle, NULL, NULL);
	sqlite3_rollback_hook(handle, NULL, NULL);
	sqlite3_update_hook(handle, NULL, NULL);

	sqlite3_busy_timeout(handle, 30000);

	sq3 = SLICE_NEW0(struct sqlx_sqlite3_s);
	sq3->db = handle;
	sq3->bd = -1;
	sq3->repo = args->repo;
	sq3->manager = args->repo->election_manager;
	NAMEFILL(sq3->name, args->name);
	g_strlcpy(sq3->path_inline, args->realpath, sizeof(sq3->path_inline));
	sq3->admin_dirty = 0;
	sq3->admin = g_tree_new_full(metautils_strcmp3, NULL, g_free, g_free);

	sqlx_exec(handle, "PRAGMA foreign_keys = OFF");

	/* We chose to check this call especially because it is able to detect
	 * a wrong/corrupted database file. */
	rc = sqlx_exec(handle, "PRAGMA journal_mode = MEMORY");
	if (rc != SQLITE_OK) {
		if (rc == SQLITE_NOTADB || rc == SQLITE_CORRUPT) {
			error = NEWERROR(CODE_CORRUPT_DATABASE,
					"invalid database file: (%d) %s",
					rc, sqlite_strerror(rc));
			sq3->corrupted = TRUE;
			__close_base(sq3);
		} else {
			error = NEWERROR(CODE_INTERNAL_ERROR,
					"failed to setup base: (%d) %s",
					rc, sqlite_strerror(rc));
		}
		return error;
	}

	sqlx_exec(handle, "PRAGMA temp_store = MEMORY");
	if (!_schema_has(sq3->db)) {
		if (_page_size >= 512) {
			gchar line[128] = {0};
			snprintf(line, sizeof(line),
					"PRAGMA page_size = %u;", _page_size);
			sqlx_exec(sq3->db, line);
		}
		sqlx_exec(sq3->db, "PRAGMA synchronous = OFF;");
		sqlx_exec(sq3->db, "BEGIN");
		_schema_apply (sq3->db, args->schema);
	} else {
		sqlx_exec(sq3->db, "BEGIN");
	}
	sqlx_admin_load (sq3);
	sqlx_admin_ensure_versions (sq3);
	sqlx_admin_set_str (sq3, SQLX_ADMIN_BASENAME, sq3->name.base);
	sqlx_admin_set_str (sq3, SQLX_ADMIN_BASETYPE, sq3->name.type);
	sqlx_admin_save_lazy (sq3);
	sqlx_exec (handle, "COMMIT");

	/* Lazy DB config */
	if (args->is_replicated) {
		sqlx_exec(handle, _get_pragma_sync(args->repo->sync_mode_repli));
	} else {
		sqlx_exec(handle, _get_pragma_sync(args->repo->sync_mode_solo));
	}

	*result = sq3;
	return NULL;
}

static GError*
__open_maybe_cached(struct open_args_s *args, struct sqlx_sqlite3_s **result)
{
	GError *e0;
	gint bd = -1;

	e0 = sqlx_cache_open_and_lock_base(args->repo->cache, args->realname,
		   args->urgent, &bd, args->deadline);
	if (e0 != NULL) {
		g_prefix_error(&e0, "cache error: ");
		return e0;
	}

	*result = sqlx_cache_get_handle(args->repo->cache, bd);
	GRID_TRACE("Cache slot reserved bd=%d, base [%s][%s] %s open",
				bd, args->name.base, args->name.type,
				(*result != NULL) ? "already" : "not");

	if (NULL != *result)
		return NULL;

	if (!(e0 = __open_not_cached(args, result))) {
		(*result)->bd = bd;
		sqlx_cache_set_handle(args->repo->cache, bd, *result);
		return NULL;
	}

	GError *e1 = sqlx_cache_unlock_and_close_base(args->repo->cache, bd, FALSE);
	if (e1) {
		GRID_WARN("BASE unlock/close error on bd=%d : (%d) %s",
				bd, e1->code, e1->message);
		g_clear_error(&e1);
	}

	GRID_DEBUG("Opening error : (%d) %s", e0->code, e0->message);
	return e0;
}

static GError*
_open_and_lock_base(struct open_args_s *args, enum election_status_e expected,
		struct sqlx_sqlite3_s **result, gchar **pmaster)
{
	GError *err = NULL;
	enum election_status_e status = 0;

	gboolean election_configured = election_manager_configured(
			args->repo->election_manager);

	if (election_configured && !args->no_refcheck) {
		gboolean has_peers = FALSE;
		err = election_has_peers(args->repo->election_manager, &args->name,
				FALSE, &has_peers);
		if (err != NULL) {
			g_prefix_error(&err, "Peers resolution error: ");
			return err;
		}
		if (has_peers)
			args->is_replicated = TRUE;
	}

	/* Now manage the replication status */
	if (!expected || !election_configured || !args->is_replicated) {
		GRID_TRACE("No status (%d) expected on [%s][%s] (peers found: %s)",
				expected, args->name.base, args->name.type,
				args->is_replicated ? "true" : "false");
	} else {
		gchar *url = NULL;

		status = election_get_status(args->repo->election_manager,
				&args->name, &url, args->deadline);
		GRID_TRACE("Status got=%d expected=%d master=%s", status, expected, url);

		switch (status) {
			case ELECTION_LOST:
				if (pmaster && url)
					*pmaster = g_strdup(url);
				if (!(expected & ELECTION_LOST)) {
					if (expected == ELECTION_LEADER)
						err = NEWERROR(CODE_REDIRECT, "%s", url);
					else
						err = NEWERROR(CODE_BADOPFORSLAVE, "not SLAVE");
				}
				break;
			case ELECTION_LEADER:
				if (!(expected & ELECTION_LEADER))
					err = NEWERROR(CODE_BADOPFORSLAVE, "not SLAVE");
				break;
			case ELECTION_FAILED:
				err = NEWERROR(CODE_UNAVAILABLE, "Election failed [%s][%s]",
						args->name.base, args->name.type);
				break;
		}

		g_free0(url);
	}

	if (!err)
		err = args->repo->cache
			? __open_maybe_cached(args, result)
			: __open_not_cached(args, result);
	if (!err) {
		if ((*result)->admin_dirty)
			sqlx_alert_dirty_base (*result, "opened with dirty admin");
		(*result)->election = status;
	}

	if (!err && args->is_replicated) {
		NAME2CONST(n, (*result)->name);
		gchar **peers = NULL;
		err = sqlx_repository_get_peers((*result)->repo, &n, &peers);
		if (err) {
			GRID_WARN("Failed to fetch peers for %s (%d %s), "
					"the local entry may remain uninitialized",
					(*result)->path_inline, err->code, err->message);
			EXTRA_ASSERT(peers == NULL);
			g_clear_error(&err);
		} else {
			EXTRA_ASSERT(peers != NULL);
			// The list returned by `get_peers` does not include this service
			gchar *myid = g_strdup(
					election_manager_get_local((*result)->manager));
			peers = oio_strv_append(peers, myid);
			if (sqlx_admin_ensure_peers((*result), peers)) {
				sqlx_admin_save_lazy(*result);
				GRID_DEBUG("Replications peers saved in %s",
						(*result)->path_inline);
			}
			g_strfreev(peers);
		}
	}

	return err;
}

/* ------------------------------------------------------------------------- */

GError*
sqlx_repository_unlock_and_close2(struct sqlx_sqlite3_s *sq3, guint32 flags)
{
	GError * err=NULL;
	EXTRA_ASSERT(sq3 != NULL);

	GRID_TRACE2("Closing bd=%d [%s][%s]", sq3->bd,
			sq3->name.base, sq3->name.type);

	sq3->election = 0;

	if (sq3->admin_dirty)
		sqlx_alert_dirty_base(sq3, "closing with dirty admin");

	if (!sq3->repo->flag_delete_on)
		sq3->deleted = FALSE;

	if (sq3->repo->cache) {
		err = sqlx_cache_unlock_and_close_base(sq3->repo->cache, sq3->bd,
				sq3->deleted ||
				sq3->corrupted ||
				(flags & SQLX_CLOSE_IMMEDIATELY));
	}
	else {
		__close_base(sq3);
	}

	return err;
}

GError*
sqlx_repository_unlock_and_close(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_repository_unlock_and_close2(sq3, 0);
}

void
sqlx_repository_unlock_and_close_noerror2(struct sqlx_sqlite3_s *sq3,
		guint32 flags)
{
	GRID_TRACE2("%s(%p)", __FUNCTION__, sq3);
	GError *e = sqlx_repository_unlock_and_close2(sq3, flags);
	if (e) {
		GRID_WARN("DB closure error: (%d) %s", e->code, e->message);
		g_error_free(e);
	}
}

void
sqlx_repository_unlock_and_close_noerror(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_repository_unlock_and_close_noerror2(sq3, 0);
}

const char *
sqlx_opentype_to_str (enum sqlx_open_type_e type, char *buf)
{
	char *p = buf;
	void append(char c) { (*p++) = c; (*p) = '\0'; }
	*buf = '\0';
	switch (type & SQLX_OPEN_REPLIMODE) {
		case SQLX_OPEN_LOCAL:
			append('L');
			break;
		case SQLX_OPEN_MASTERONLY:
			append('M');
			break;
		case SQLX_OPEN_SLAVEONLY:
			append('S');
			break;
		case SQLX_OPEN_MASTERSLAVE:
			append('M'), append('S');
			break;
	}

	if (type & SQLX_OPEN_CREATE)
		append('C');
	if (type & SQLX_OPEN_NOREFCHECK)
		append('N');

	if (!(type & SQLX_OPEN_STATUS))
		append('E'), append('F'), append('D');
	else {
		if (type & SQLX_OPEN_ENABLED) append ('E');
		if (type & SQLX_OPEN_FROZEN) append ('F');
		if (type & SQLX_OPEN_DISABLED) append ('D');
	}
	return buf;
}

GError*
sqlx_repository_open_and_lock(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, enum sqlx_open_type_e how,
		struct sqlx_sqlite3_s **result, gchar **lead)
{
	return sqlx_repository_timed_open_and_lock(
			repo, n, how, result, lead, oio_ext_get_deadline());
}

GError*
sqlx_repository_timed_open_and_lock(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, enum sqlx_open_type_e how,
		struct sqlx_sqlite3_s **result, gchar **lead,
		gint64 deadline)
{
	GError *err = NULL;
	struct open_args_s args = {0};

	EXTRA_ASSERT(repo != NULL);
	SQLXNAME_CHECK(n);
	GRID_TRACE("%s (%s,%s)", __FUNCTION__, n->base, n->type);

	if (result)
		*result = NULL;

	if (!repo->running)
		return NEWERROR(CODE_UNAVAILABLE, "Repository being closed");

	if (NULL != (err = _open_fill_args(&args, repo, n)))
		return err;
	args.no_refcheck = BOOL(how & SQLX_OPEN_NOREFCHECK);
	args.create = BOOL(how & SQLX_OPEN_CREATE);
	args.urgent = BOOL(how & SQLX_OPEN_URGENT);
	args.deadline = deadline;

	switch (how & SQLX_OPEN_REPLIMODE) {
		case SQLX_OPEN_LOCAL:
			err = _open_and_lock_base(&args, 0, result, NULL);
			break;
		case SQLX_OPEN_MASTERSLAVE:
			err = _open_and_lock_base(&args, ELECTION_LEADER|ELECTION_LOST,
					result, lead);
			break;
		case SQLX_OPEN_MASTERONLY:
			err = _open_and_lock_base(&args, ELECTION_LEADER, result, NULL);
			break;
		case SQLX_OPEN_SLAVEONLY:
			err = _open_and_lock_base(&args, ELECTION_LOST, result, lead);
			break;
		default:
			GRID_ERROR("sqlx_repository_open_and_lock(how=%d/%x)", how, how);
			g_assert_not_reached();
	}

	if (!err) {
		gint64 expected_status = how & SQLX_OPEN_STATUS;
		if (expected_status) {

			gint64 flags = sqlx_admin_get_status(*result);
			gint64 mode = SQLX_OPEN_ENABLED;
			if (flags == ADMIN_STATUS_FROZEN)
				mode = SQLX_OPEN_FROZEN;
			else if (flags == ADMIN_STATUS_DISABLED)
				mode = SQLX_OPEN_DISABLED;

			if (!(mode & expected_status)) {
				err = NEWERROR(CODE_CONTAINER_FROZEN, "Invalid status");
				sqlx_repository_unlock_and_close_noerror(*result);
			}
		}
	}

	_open_clean_args(&args);

	/* XXX(jfs): patching the db handle so it has the lastest election_manager
	   allows reusing a handle from the cache, and that was initiated during
	   the _post_config hook (when the election_manager was not associated yet
	   to the repository. */
	if (!err && result)
		(*result)->manager = repo->election_manager;

	if (!err && repo->open_callback && result) {
		err = repo->open_callback(*result, repo->open_callback_data);
		if (err) {
			sqlx_repository_unlock_and_close_noerror(*result);
			if (lead && *lead) {
				g_free(*lead);
				*lead = NULL;
			}
		}
	}

	return err;
}

GError*
sqlx_repository_has_base2(sqlx_repository_t *repo, const struct sqlx_name_s *n,
		gchar** bddname)
{
	REPO_CHECK(repo);
	SQLXNAME_CHECK(n);

	struct open_args_s args = {0};

	if (bddname != NULL)
		*bddname = NULL;

	GError *err = _open_fill_args(&args, repo, n);
	if (NULL != err)
		return err;

	if (!g_file_test(args.realpath, G_FILE_TEST_EXISTS))
		err = NEWERROR(CODE_CONTAINER_NOTFOUND, "Container not found"
				" : (%d) %s", errno, strerror(errno));

	if (bddname != NULL)
		*bddname = g_strdup(args.realpath);
	_open_clean_args(&args);
	return err;
}

/* ------------------------------------------------------------------------- */

GError*
sqlx_repository_status_base(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, gint64 deadline)
{
	REPO_CHECK(repo);
	SQLXNAME_CHECK(n);

	GError *err = NULL;
	gboolean has_peers = FALSE;

	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, n->type, n->base);

	if (!repo->running)
		return NEWERROR(CODE_UNAVAILABLE, "Repository being shut down");

	if (NULL != (err = _schema_get(repo, n->type, NULL)))
		return err;

	if (!election_manager_configured(repo->election_manager)) {
		GRID_TRACE("Replication disabled by configuration, MASTER de facto");
		return NULL;
	}

	err = election_has_peers(repo->election_manager, n, FALSE, &has_peers);
	if (err != NULL) {
		g_prefix_error(&err, "Peers resolution error: ");
		return err;
	}

	if (!has_peers) {
		GRID_TRACE("Unable to find peers for [%s][%s]", n->base, n->type);
		return NULL;
	}

	gchar *url = NULL;
	enum election_status_e status;

	status = election_get_status(repo->election_manager, n, &url, deadline);
	switch (status) {
		case ELECTION_LOST:
			err = NEWERROR(CODE_REDIRECT, "%s", url);
			break;
		case ELECTION_LEADER:
			err = NULL;
			break;
		case ELECTION_FAILED:
			err = NEWERROR(CODE_INTERNAL_ERROR,
					"Election failed for %s.%s", n->base, n->type);
			break;
	}

	g_free0(url);
	return err;
}

GError*
sqlx_repository_prepare_election(sqlx_repository_t *repo, const struct sqlx_name_s *n)
{
	REPO_CHECK(repo);
	SQLXNAME_CHECK(n);

	GError *err;
	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, n->type, n->base);

	if (!repo->running)
		return NEWERROR(CODE_UNAVAILABLE, "Repository being shut down");

	if (NULL != (err = _schema_get(repo, n->type, NULL)))
		return err;

	if (!election_manager_configured(repo->election_manager)) {
		GRID_TRACE("Replication disabled by configuration");
		return NULL;
	}

	return election_init(repo->election_manager, n);
}

GError*
sqlx_repository_exit_election(sqlx_repository_t *repo, const struct sqlx_name_s *n)
{
	REPO_CHECK(repo);
	SQLXNAME_CHECK(n);

	GError *err;
	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, n->type, n->base);

	if (!repo->running)
		return NEWERROR(CODE_UNAVAILABLE, "Repository being shut down");

	if (NULL != (err = _schema_get(repo, n->type, NULL)))
		return err;

	if (!repo->election_manager) {
		GRID_TRACE("Replication disabled by configuration");
		return NULL;
	}

	err = election_exit(repo->election_manager, n);
	return err;
}

GError*
sqlx_repository_use_base(sqlx_repository_t *repo, const struct sqlx_name_s *n)
{
	REPO_CHECK(repo);
	SQLXNAME_CHECK(n);
	GError *err;

	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, n->type, n->base);

	if (!repo->running)
		return NEWERROR(CODE_UNAVAILABLE, "Repository being shut down");

	if (NULL != (err = _schema_get(repo, n->type, NULL)))
		return err;

	if (!election_manager_configured(repo->election_manager)) {
		GRID_TRACE("Replication disabled by configuration");
		return NULL;
	}

	return election_start(repo->election_manager, n);
}

/* ------------------------------------------------------------------------- */

static GError*
_backup_main(sqlite3 *src, sqlite3 *dst)
{
	int rc;
	sqlite3_backup *backup;
	GError *err = NULL;

	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, src, dst);

	backup = sqlite3_backup_init(dst, "main", src, "main");

	if (!backup)
		err = NEWERROR(sqlite3_errcode(dst), "%s", sqlite3_errmsg(dst));
	else {
		while (SQLITE_OK == (rc = sqlite3_backup_step(backup, 1))) {}
		if (rc != SQLITE_DONE)
			err = NEWERROR(CODE_INTERNAL_ERROR, "backup error: (%d) %s", rc,
					sqlite_strerror(rc));
		(void) sqlite3_backup_finish(backup);
	}

	GRID_TRACE("Backup %s!", err ? "failed" : "done");
	return err;
}

static GError*
_read_file_chunk(int fd, guint64 chunk_size, GByteArray *gba)
{
	ssize_t r;
	guint64 tot = 0;
	guint8 *d;
	GError *err = NULL;

	d = g_malloc(SQLX_DUMP_BUFFER_SIZE);

	do {
		r = read(fd, d, MIN(chunk_size - tot, SQLX_DUMP_BUFFER_SIZE));
		if (r < 0) {
			err = NEWERROR(errno, "read error: %s", strerror(errno));
		} else if (r > 0) {
			tot += r;
			g_byte_array_append(gba, d, r);
		}
	} while (r > 0 && tot < chunk_size && !err);

	g_free(d);
	return err;
}

static GError*
_read_file(int fd, GByteArray *gba)
{
	int rc;
	struct stat st;
	GError *err = NULL;

	rc = fstat(fd, &st);
	GRID_TRACE2("%s(%d,%p) size=%"G_GINT64_FORMAT, __FUNCTION__, fd,
			gba, st.st_size);

	if (0 > rc)
		return NEWERROR(errno, "Failed to stat the temporary base");

	g_byte_array_set_size(gba, st.st_size);
	g_byte_array_set_size(gba, 0);

	err = _read_file_chunk(fd, (guint64)st.st_size, gba);
	return err;
}

GError*
sqlx_repository_backup_base(struct sqlx_sqlite3_s *src_sq3,
		struct sqlx_sqlite3_s *dst_sq3)
{
	EXTRA_ASSERT(src_sq3 != NULL);
	EXTRA_ASSERT(dst_sq3 != NULL);
	return _backup_main(src_sq3->db, dst_sq3->db);
}

GError*
sqlx_repository_dump_base_fd(struct sqlx_sqlite3_s *sq3,
		dump_base_fd_cb read_file_cb, gpointer cb_arg)
{
	gchar path[LIMIT_LENGTH_VOLUMENAME+32] = {0};
	gboolean try_slash_tmp = FALSE;
	int rc, fd;
	sqlite3 *dst = NULL;
	GError *err = NULL;

	GRID_TRACE2("%s(%p,%p,%p)", __FUNCTION__, sq3, read_file_cb, cb_arg);
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(read_file_cb != NULL);

	do {
		/* First try to dump on local volume, on error try /tmp */
		g_snprintf(path, sizeof(path), "%s/tmp/dump.sqlite3.XXXXXX",
				try_slash_tmp? "" : sq3->repo->basedir);

		if (0 > (fd = g_mkstemp(path))) {
			err = NEWERROR(errno, "Temporary file creation error: %s",
					strerror(errno));
		} else {
			GRID_TRACE("DUMP to [%s] fd=%d from bd=[%s][%s]", path, fd,
					sq3->name.base, sq3->name.type);

			/* TODO : provides a VFS dumping everything in memory */
			rc = sqlite3_open_v2(path, &dst, SQLITE_OPEN_PRIVATECACHE
					|SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE, NULL);

			if (rc != SQLITE_OK) {
				err = NEWERROR(rc,
						"sqlite3_open error: (%s) (errno=%d) %s",
						sqlite_strerror(rc), errno, strerror(errno));
			} else {
				err = _backup_main(sq3->db, dst);
			}
			_close_handle(&dst);
			unlink(path);
		}

		if (err && !try_slash_tmp) {
			GRID_WARN("Failed to dump base into %s (%s), will try with /tmp",
					path, err->message);
			g_clear_error(&err);
			try_slash_tmp = TRUE;
		} else {
			break;
		}
	} while (1);

	if (!err) {
		err = read_file_cb(fd, cb_arg);
	}

	metautils_pclose(&fd);
	return err;
}

GError*
sqlx_repository_dump_base_gba(struct sqlx_sqlite3_s *sq3, GByteArray **dump)
{
	GError *_monolytic_dump_cb(int fd, gpointer arg)
	{
		GError *_err = NULL;
		GByteArray **dump2 = arg;
		GByteArray *_dump = g_byte_array_sized_new(128 * 1024);
		_err = _read_file(fd, _dump);
		if (!_err)
			*dump2 = _dump;
		else
			g_byte_array_free(_dump, TRUE);
		return _err;
	}
	return sqlx_repository_dump_base_fd(sq3, _monolytic_dump_cb, dump);
}

GError*
sqlx_repository_dump_base_chunked(struct sqlx_sqlite3_s *sq3,
		gint chunk_size, dump_base_chunked_cb callback, gpointer callback_arg)
{
	GError *_chunked_dump_cb(int fd, gpointer arg)
	{
		(void) arg;
		int rc;
		gint64 bytes_read = 0;
		struct stat st;
		GError *err = NULL;

		rc = fstat(fd, &st);
		if (0 > rc)
			return NEWERROR(errno, "Failed to stat the temporary base");
		do {
			GByteArray *gba = g_byte_array_sized_new(128 * 1024);
			err = _read_file_chunk(fd, chunk_size, gba);
			if (!err) {
				bytes_read += gba->len;
				err = callback(gba, st.st_size - bytes_read, callback_arg);
			}
		} while (!err && bytes_read < st.st_size);
		return err;
	}
	return sqlx_repository_dump_base_fd(sq3, _chunked_dump_cb, NULL);
}

GError*
sqlx_repository_restore_from_file(struct sqlx_sqlite3_s *sq3,
		const gchar *path)
{
	int rc;
	sqlite3 *src = NULL;
	GError *err = NULL;

	/* Tries to open the temporary file as a SQLite3 DB */
	rc = sqlite3_open_v2(path, &src,
			SQLITE_OPEN_READONLY, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE) {
		_close_handle(&src);
		err = NEWERROR(rc,
				"sqlite3_open error: (%s) (errno=%d) %s",
				sqlite_strerror(rc), errno, strerror(errno));
		g_prefix_error(&err, "Invalid raw SQLite base: ");
	} else { /* Backup now! */
		err = _backup_main(src, sq3->db);
		_close_handle(&src);
		sqlx_admin_reload(sq3);
	}

	return err;
}

GError*
sqlx_repository_restore_base(struct sqlx_sqlite3_s *sq3, guint8 *raw, gsize rawsize)
{
	gboolean try_slash_tmp = FALSE;
	gchar path[LIMIT_LENGTH_VOLUMENAME+32] = {0};
	GError *err = NULL;
	struct restore_ctx_s *restore_ctx = NULL;

	GRID_TRACE2("%s(%p,%p,%"G_GSIZE_FORMAT")", __FUNCTION__, sq3,
			raw, rawsize);
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(raw != NULL);
	EXTRA_ASSERT(rawsize > 0);

	do {
		g_snprintf(path, sizeof(path), "%s/tmp/restore.sqlite3.XXXXXX",
				try_slash_tmp? "" : sq3->repo->basedir);

		/* fills a temporary file */
		err = restore_ctx_create(path, &restore_ctx);
		if (err != NULL) {
			g_prefix_error(&err, "Failed to create restore context into %s: ",
					path);
		} else {
			err = restore_ctx_append(restore_ctx, raw, rawsize);
			if (err != NULL) {
				g_prefix_error(&err, "Failed to fill temp file %s: ",
						path);
			}
		}

		if (err && !try_slash_tmp) {
			GRID_WARN("%s, will try with /tmp", err->message);
			restore_ctx_clear(&restore_ctx);
			g_clear_error(&err);
			try_slash_tmp = TRUE;
		} else {
			break;
		}
	} while (1);

	if (!err) {
		EXTRA_ASSERT(restore_ctx->fd >= 0);
		err = sqlx_repository_restore_from_file(sq3, restore_ctx->path);
	}
	restore_ctx_clear(&restore_ctx);

	if (err)
		GRID_ERROR("Failed to restore base: %s", err->message);

	GRID_TRACE("Base restored? (%d) %s", err?err->code:0,
			err?err->message:"OK");
	return err;
}

GError*
sqlx_repository_retore_from_master(struct sqlx_sqlite3_s *sq3)
{
	EXTRA_ASSERT(sq3 != NULL);
	NAME2CONST(n, sq3->name);
	return !election_manager_configured(sq3->repo->election_manager)
		? NEWERROR(CODE_INTERNAL_ERROR, "Replication not configured")
		: election_manager_trigger_RESYNC(sq3->repo->election_manager, &n);
}

GError*
sqlx_repository_get_peers(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, gchar ***result)
{
	return election_get_peers(repo->election_manager, n, FALSE, result);
}

GError*
sqlx_repository_get_peers2(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, gchar ***result)
{
	REPO_CHECK(repo);
	SQLXNAME_CHECK(n);
	EXTRA_ASSERT(result != NULL);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = sqlx_repository_open_and_lock(repo, n, SQLX_OPEN_LOCAL|SQLX_OPEN_NOREFCHECK, &sq3, NULL);
	if (err) {
		*result = NULL;
	} else {
		gchar *tmp = sqlx_admin_get_str(sq3, SQLX_ADMIN_PEERS);
		sqlx_repository_unlock_and_close_noerror2(sq3, SQLX_CLOSE_IMMEDIATELY);
		if (tmp) {
			*result = g_strsplit(tmp, ",", -1);
			g_free(tmp);
		} else {
			*result = g_malloc0(sizeof(gchar*));
		}
	}
	return err;
}

GError *
sqlx_repository_get_version(struct sqlx_sqlite3_s *sq3, GTree **result)
{
	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, sq3, result);
	if (!sq3 || !result)
		return BADREQ("Invalid parameter");
	*result = version_extract_from_admin(sq3);
	return NULL;
}

GError *
sqlx_repository_get_version2(sqlx_repository_t *repo, const struct sqlx_name_s *n,
		GTree **result)
{
	REPO_CHECK(repo);
	SQLXNAME_CHECK(n);
	EXTRA_ASSERT(result != NULL);

	GRID_TRACE2("%s(%p,%s,%s)", __FUNCTION__, repo, n->type, n->base);

	GError *err;
	GTree *version = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	*result = NULL;
	err = sqlx_repository_open_and_lock(repo, n, SQLX_OPEN_LOCAL, &sq3, NULL);
	if (NULL != err)
		return err;

	err = sqlx_repository_get_version(sq3, &version);
	sqlx_repository_unlock_and_close_noerror(sq3);
	if (NULL != err) {
		EXTRA_ASSERT(version == NULL);
		return err;
	}

	*result = version;
	return NULL;
}

