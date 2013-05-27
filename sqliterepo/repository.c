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

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.cache"
#endif

#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <glib.h>
#include <sqlite3.h>

#include "../metautils/lib/metatypes.h"
#include "../metautils/lib/metautils.h"
#include "../metautils/lib/metacomm.h"
#include "../metautils/lib/loggers.h"
#include "../metautils/lib/volume_lock.h"

#include "./internals.h"
#include "./sqliterepo.h"
#include "./hash.h"
#include "./cache.h"
#include "./election.h"
#include "./version.h"
#include "./sqlite_utils.h"

#define GSTR_APPEND_SEP(S) do { \
	if ((S)->str[(S)->len-1]!=G_DIR_SEPARATOR) \
			g_string_append_c((S), G_DIR_SEPARATOR); \
} while (0)

static GQuark gquark_log = 0;

struct sqlx_repository_s
{
	gchar basedir[512];

	guint hash_width;
	guint hash_depth;

	guint bases_count;
	guint bases_max;

	gboolean flag_autocreate;
	gboolean flag_autovacuum;
	gboolean flag_delete_on;

	GHashTable *schemas;

	sqlx_cache_t *cache;

	struct election_manager_s *election_manager;
	sqlx_file_locator_f locator;
	gpointer locator_data;

	sqlx_repo_close_hook close_callback;
	gpointer close_callback_data;

	sqlx_repo_open_hook open_callback;
	gpointer open_callback_data;
};

static gchar*
compute_path(sqlx_repository_t *repo, const hashstr_t *hn, const gchar *t)
{
	guint w, d, i = 0;
	gsize nlen;
	GString *gstr;
	const gchar *n;

	n = hashstr_str(hn);
	nlen = hashstr_len(hn);
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

static inline const char const *
__op2str(int op)
{
	switch (op) {
		case SQLITE_INSERT:
			return "INSERT";
		case SQLITE_UPDATE:
			return "UPDATE";
		case SQLITE_DELETE:
			return "DELETE";
		default:
			return "??????";
	}
}

static void
__delete_base(struct sqlx_sqlite3_s *sq3)
{
	if (!sq3->path) {
		GRID_WARN("DELETE disabled [%s][%s]",
				sq3->logical_name, sq3->logical_type);
		return;
	}

	if (!unlink(sq3->path))
		GRID_DEBUG("DELETE done [%s][%s] (%s)", sq3->logical_name,
			sq3->logical_type, sq3->path);
	else
		GRID_WARN("DELETE failed [%s][%s] (%s) : (%d) %s",
				sq3->logical_name, sq3->logical_type, sq3->path,
				errno, strerror(errno));
	sq3->deleted = 0;
}

static void
__close_base(struct sqlx_sqlite3_s *sq3)
{
	if (!sq3) {
		GRID_DEBUG("Closing a NULL db handle");
		return;
	}

	GRID_TRACE2("DB being closed [%s][%s]", sq3->logical_name,
			sq3->logical_type);

	/* send a vacuum */
	if (sq3->repo && sq3->repo->flag_autovacuum)
		sqlx_exec(sq3->db, "VACUUM");

	/* delete the base */
	if (sq3->deleted)
		__delete_base(sq3);

	/* Clean the structure */
	if (sq3->db)
		sqlite3_close(sq3->db);
	if (sq3->logical_name)
		g_free(sq3->logical_name);
	if (sq3->logical_type)
		g_free(sq3->logical_type);
	if (sq3->path)
		g_free(sq3->path);
	if (sq3->versions)
		g_tree_destroy(sq3->versions);

	memset(sq3, 0, sizeof(*sq3));
	sq3->bd = -1;
	g_free(sq3);
}

static void
__clean_schema(gpointer v)
{
	if (!v)
		return;
	g_byte_array_free((GByteArray*)v, TRUE);
}

static GError*
__file_read(const gchar *path, GByteArray **raw)
{
	GError *error = NULL;
	gchar *content = NULL;
	gsize content_size = 0;

	if (!g_file_get_contents(path, &content, &content_size, &error))
		return error;
	if (!error)
		*raw = g_byte_array_append(g_byte_array_new(),
				(guint8*)content, content_size);
	if (content)
		g_free(content);
	return error;
}

static GError*
__test_schema(const gchar *schema, const gchar *version, GByteArray **raw)
{
	gchar *tmp_path;
	int rc;
	char *errmsg = NULL;
	GError *error = NULL;
	sqlite3 *db = NULL;

	tmp_path = g_strdup_printf("/tmp/schema.%d.%ld.sqlite",
			getpid(), time(0));

	/* Open a new base */
	rc = sqlite3_open_v2(tmp_path, &db, SQLITE_OPEN_NOMUTEX
			|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE, NULL);
	if (rc != SQLITE_OK) {
		error = g_error_new(gquark_log, rc, "SQLite error [%s]: (%d) %s",
				tmp_path, rc, sqlite3_errmsg(db));
		db = NULL;
		goto label_exit;
	}

	/* Force an admin table */
	rc = sqlite3_exec(db, "CREATE TABLE admin ("
				"k TEXT PRIMARY KEY NOT NULL, v BLOB DEFAULT NULL)",
				NULL, NULL, &errmsg);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)  {
		error = g_error_new(gquark_log, rc, "Admin table error : %s (%s)",
			sqlite3_errmsg(db), errmsg);
		goto label_exit;
	}

	if (version && *version)
		sqlx_set_admin_entry_noerror(db, "schema_version", version);

	/* Apply the schema in it */
	rc = sqlite3_exec(db, schema, NULL, NULL, &errmsg);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)  {
		error = g_error_new(gquark_log, rc, "Schema error : %s (%s)",
			sqlite3_errmsg(db), errmsg);
		goto label_exit;
	}

	/* We can close the file */
	(void) sqlite3_close(db);
	db = NULL;

	/* Load the whole file */
	error = __file_read(tmp_path, raw);

label_exit:
	if (db)
		(void) sqlite3_close(db);
	if (errmsg)
		sqlite3_free(errmsg);
	unlink(tmp_path);
	g_free(tmp_path);
	return error;
}

static GError*
__get_schema(sqlx_repository_t *repo, const gchar *type, GByteArray **res)
{
	const gchar *subtype;
	GByteArray *raw;
	hashstr_t *ht;

	if (NULL != (subtype = strchr(type, '.'))) {
		HASHSTR_ALLOCA_LEN(ht, type, subtype-type);
	}
	else {
		HASHSTR_ALLOCA(ht, type);
	}

	raw = g_hash_table_lookup(repo->schemas, ht);
	if (!raw)
		return (subtype != NULL)
			? (g_error_new(gquark_log, EINVAL, "Unmanaged schema type [%s] [%s]", hashstr_str(ht), type))
			: (g_error_new(gquark_log, EINVAL, "Unmanaged schema type [%s]", hashstr_str(ht)));

	if (res)
		*res = raw;
	return NULL;
}


/* ------------------------------------------------------------------------- */


GError *
sqlx_repository_init(const gchar *vol, struct sqlx_repo_config_s *cfg,
		sqlx_repository_t **result)
{
	struct stat s;
	sqlx_repository_t *repo;

	(void) sqlite3_initialize();

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	if (!sqlite3_threadsafe())
		return g_error_new(gquark_log, 0, "SQLite not in safe mode");

	SQLX_ASSERT(vol != NULL);
	SQLX_ASSERT(*vol != '\0');
	SQLX_ASSERT(result != NULL);

	/* Check the rights on the volume */
	if (-1 == stat(vol, &s))
		return g_error_new(gquark_log, errno,
				"Invalid directory : %s", strerror(errno));

	if (!S_ISDIR(s.st_mode))
		return g_error_new(gquark_log, errno,
				"Invalid directory : not a directory");

	int ok_usr = ((s.st_mode & S_IRWXU) == S_IRWXU);
	int ok_grp = ((s.st_mode & S_IRWXG) == S_IRWXG);
	int ok_oth = ((s.st_mode & S_IRWXO) == S_IRWXO);
	int ok = !getuid() /* especially for root */
		||  ok_oth
		|| (ok_grp && getgid() == s.st_gid)
		|| (ok_usr && getuid() == s.st_uid);

	if (!ok)
		return g_error_new(gquark_log, errno,
				"Invalid directory : insufficient permissions");

	/* Lock the volume with XATTR */
	if (cfg != NULL) {
		if (!(cfg->flags & SQLX_REPO_NOLOCK)) {
			GError *err = volume_service_lock(vol, cfg->lock.type,
						cfg->lock.srv, cfg->lock.ns);
			if (err != NULL)
				return err;
		}
	}

	repo = g_malloc0(sizeof(*repo));
	g_strlcpy(repo->basedir, vol, sizeof(repo->basedir)-1);
	repo->hash_depth = 2;
	repo->hash_width = 2;

	repo->schemas = g_hash_table_new_full(
			(GHashFunc)hashstr_hash, (GEqualFunc)hashstr_equal,
			g_free, __clean_schema);

	repo->flag_autocreate = !cfg ? TRUE : (cfg->flags & SQLX_REPO_AUTOCREATE);
	repo->flag_autovacuum = !cfg ? FALSE : (cfg->flags & SQLX_REPO_VACUUM);
	repo->flag_delete_on = !cfg ? FALSE : (cfg->flags & SQLX_REPO_DELETEON);

	if (!cfg || !(cfg->flags & SQLX_REPO_NOCACHE)) {
		repo->cache = sqlx_cache_init();
		sqlx_cache_set_close_hook(repo->cache,
				(sqlx_cache_close_hook)__close_base);
	}

	*result = repo;
	return NULL;
}

void
sqlx_repository_clean(sqlx_repository_t *repo)
{
	if (!repo)
		return;

	if (repo->cache) {
		sqlx_cache_expire(repo->cache, G_MAXUINT, NULL, NULL);
		sqlx_cache_clean(repo->cache);
	}

	if (repo->schemas)
		g_hash_table_destroy(repo->schemas);

	if (repo->election_manager)
		election_manager_clean(repo->election_manager);

	memset(repo, 0, sizeof(*repo));
	g_free(repo);
}

void
sqlx_repository_configure_hash(sqlx_repository_t *repo,
		guint width, guint depth)
{
	SQLX_ASSERT(repo != NULL);

	/* some sanity checks */
	if (width > 4)
		GRID_WARN("width = %u be careful to the number of files in each level", width);
	if (depth > 4)
		GRID_WARN("depth = %u be careful to the number of directores", depth);
	if (width * depth > 6)
		GRID_WARN("strange hash size (%u)", width * depth);

	repo->hash_depth = depth;
	repo->hash_width = width;
	GRID_INFO("Repository path hash configured : depth=%u width=%u",
		repo->hash_depth, repo->hash_width);
}

void
sqlx_repository_configure_maxbases(sqlx_repository_t *repo, guint max)
{
	guint max_bases, max_clients;

	GRID_TRACE2("%s(%p,%u)", __FUNCTION__, repo, max);
	g_assert(max >= 4);

	max_clients = MAX(max/5, 5);
	max_bases = max - max_clients;

	SQLX_ASSERT(repo != NULL);
	SQLX_ASSERT(repo->bases_count == 0);

	if (repo->cache)
		sqlx_cache_set_max_bases(repo->cache, max_bases);
	if (repo->election_manager)
		election_manager_clients_setmax(repo->election_manager, max_clients);

	repo->bases_count = 0;
	repo->bases_max = max_bases;
}

GError*
sqlx_repository_configure_type(sqlx_repository_t *repo,
		const gchar *type, const gchar *version, const gchar *schema)
{
	GByteArray *raw = NULL;
	GError *error = NULL;

	SQLX_ASSERT(repo != NULL);
	SQLX_ASSERT(type != NULL);
	SQLX_ASSERT(schema != NULL);

	if (NULL != (error = __test_schema(schema, version, &raw)))
		return error;

	g_hash_table_insert(repo->schemas, hashstr_create(type), raw);
	GRID_INFO("Schema configured for type [%s]", type);
	GRID_DEBUG("Schema [%s] : %s", type, schema);
	return NULL;
}

void
sqlx_repository_configure_close_callback(sqlx_repository_t *repo,
		sqlx_repo_close_hook cb, gpointer cb_data)
{
	SQLX_ASSERT(repo != NULL);
	SQLX_ASSERT(cb != NULL);

	repo->close_callback = cb;
	repo->close_callback_data = cb_data;
}

void
sqlx_repository_configure_open_callback(sqlx_repository_t *repo,
		sqlx_repo_open_hook cb, gpointer cb_data)
{
	SQLX_ASSERT(repo != NULL);
	SQLX_ASSERT(cb != NULL);

	repo->open_callback = cb;
	repo->open_callback_data = cb_data;
}

/* ------------------------------------------------------------------------- */


struct open_args_s
{
	struct sqlx_repository_s *repo;
	const gchar *logical_name;
	const gchar *logical_type;
	GByteArray *raw;
	hashstr_t *realname;
	gchar *realpath;
	gboolean create;
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
			error = g_error_new(gquark_log, errno, "mkdir(%s) error : %d (%s)",
					start, errno, strerror(errno));
		else {
			GRID_TRACE("mkdir(%s)", start);
		}
		*s = G_DIR_SEPARATOR;
	}

	return error;
}

static GError*
__create_base(struct open_args_s *args, gchar *path, GByteArray *raw)
{
	guint retry = 1;
	int fd;

	GRID_TRACE("DB creation attempt on [%s]", path);

	/* Create the file atomically */
label_retry:
	fd = open(path, O_CREAT|O_EXCL|O_RDWR, 0640);
	if (fd < 0) {
		switch (errno) {
			case EINTR:
				goto label_retry;
			case EEXIST:
				GRID_TRACE("[%s] already exists", path);
				return NULL;
			case ENOENT: {
				GError *err;
				if (retry--) {
					if (NULL != (err = __create_directory(path)))
						return err;
					goto label_retry;
				}
			}
			default: /* FALLTROUGH */
				return g_error_new(gquark_log, errno,
						"open(O_CREAT|O_EXCL) error : %d (%s)",
						errno, strerror(errno));
		}
	}

	/* Now fill it with the raw content */
	guint written;
	for (written=0; written < raw->len ;) {
		ssize_t w = write(fd, raw->data + written, raw->len - written);

		if (w < 0) {
			int errsav = errno;
			if (errsav == EINTR || errsav == EAGAIN)
				continue;
			unlink(path);
			close(fd);
			return g_error_new(gquark_log, errsav, "write() error : %d (%s)",
					errsav, strerror(errsav));
		}
		if (w > 0)
			written += w;
	}

	/* Save the base admin fields */
	do {
		sqlite3 *h;
		if (SQLITE_OK == sqlite3_open(path, &h)) {
			sqlx_exec(h, "BEGIN");
			sqlx_set_admin_entry_noerror(h, "base_name", args->logical_name);
			sqlx_set_admin_entry_noerror(h, "container_name", args->logical_name);
			sqlx_set_admin_entry_noerror(h, "base_type", args->logical_type);
			sqlx_exec(h, "COMMIT");
			sqlite3_close(h);
		}
	} while (0);

	close(fd);
	return NULL;
}

static GError *
_open_fill_args(struct open_args_s *args, struct sqlx_repository_s *repo,
		const gchar *t, const gchar *n)
{
	GError *err = NULL;

	memset(args, 0, sizeof(args));

	args->repo = repo;
	args->logical_type = t;
	args->logical_name = n;

	if (!repo->locator) {
		args->realname = sqliterepo_hash_name(n, t);
		args->realpath = compute_path(repo, args->realname, t);
	}
	else {
		GString *fn = g_string_new("");
		repo->locator(repo->locator_data, n, t, fn);
		args->realname = hashstr_create_from_gstring(fn);
		g_string_free(fn, TRUE);
		args->realpath = compute_path(repo, args->realname, NULL);
	}

	if (NULL != (err = __get_schema(repo, t, &(args->raw))))
		return err;


	return NULL;
}

static void
_open_clean_args(struct open_args_s *args)
{
	if (args->realname)
		g_free(args->realname);
	if (args->realpath)
		g_free(args->realpath);
}

static GError*
__open_not_cached(struct open_args_s *args, struct sqlx_sqlite3_s **result)
{
	GError *error = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;
	sqlite3 *handle = NULL;
	guint attempts = 2;
	gint rc, flags = 0;
	gboolean created = FALSE;

	/*flags |= SQLITE_OPEN_FULLMUTEX;*/
	flags |= SQLITE_OPEN_NOMUTEX;
	/*flags |= SQLITE_OPEN_SHAREDCACHE;*/
	flags |= SQLITE_OPEN_PRIVATECACHE;
	flags |= SQLITE_OPEN_READWRITE;

retry:
	switch (rc = sqlite3_open_v2(args->realpath, &handle, flags, NULL)) {
		case SQLITE_OK:
		case SQLITE_DONE:
			GRID_TRACE2("Open succeeded [%s]", args->realpath);
			break;
		case SQLITE_NOTFOUND:
		case SQLITE_CANTOPEN:
			GRID_DEBUG("Open soft error [%s] : (%d) %s", args->realpath, rc, sqlite_strerror(rc));
			if (attempts-- && (args->create || args->repo->flag_autocreate)) {
				if (!(error = __create_base(args, args->realpath, args->raw))) {
					GRID_TRACE("Base created, retrying open [%s]", args->realpath);
					created = TRUE;
					goto retry;
				}
				GRID_DEBUG("DB creation error on [%s] : (%d) %s", args->realpath, error->code, error->message);
			}
			else {
		default:
				GRID_DEBUG("Open strong error [%s] : (%d) %s", args->realpath, rc, sqlite_strerror(rc));
				error = g_error_new(gquark_log, CODE_CONTAINER_NOTFOUND,
						"sqlite3_open error: (errno=%d) %s", errno, strerror(errno));
			}
			return error;
	}

	/* Lazy DB config */
	sqlite3_busy_timeout(handle, 30000);
	sqlx_exec(handle, "PRAGMA foreign_keys = OFF");
	sqlx_exec(handle, "PRAGMA synchronous = FULL");
	sqlx_exec(handle, "PRAGMA writable_schema = FALSE");
	sqlx_exec(handle, "PRAGMA journal_mode = MEMORY");

	sq3 = g_malloc0(sizeof(*sq3));
	sq3->db = handle;
	sq3->bd = -1;
	sq3->repo = args->repo;
	sq3->config = election_manager_get_config(args->repo->election_manager);
	sq3->logical_name = g_strdup(args->logical_name);
	sq3->logical_type = g_strdup(args->logical_type);
	sq3->path = g_strdup(args->realpath);

	version_load(sq3, TRUE);
	if (created)
		version_save(sq3);

	version_debug("LOADED:", sq3->versions);

	*result = sq3;
	return NULL;
}

static GError*
__open_maybe_cached(struct open_args_s *args, struct sqlx_sqlite3_s **result)
{
	GError *e0;
	gint bd = -1;

	e0 = sqlx_cache_open_and_lock_base(args->repo->cache, args->realname, &bd);
	if (e0 != NULL) {
		g_prefix_error(&e0, "cache error: ");
		return e0;
	}

	*result = sqlx_cache_get_handle(args->repo->cache, bd);
	if (*result) {
		GRID_TRACE("Cache slot reserved bd=%d, base already open [%d][%s][%s]",
				bd, (*result)->bd, (*result)->logical_name,
				(*result)->logical_type);
		return NULL;
	}

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

	/* Now manage the replication status */
	if (!expected || !election_manager_configured(args->repo->election_manager)) {
		GRID_TRACE("No status (%d) expected on [%s][%s]", expected,
				args->logical_name, args->logical_type);
	}
	else if (!election_has_peers(args->repo->election_manager,
				args->logical_name, args->logical_type)) {
		GRID_TRACE("Unable to find peers for [%s][%s]",
				args->logical_name, args->logical_type);
	}
	else {
		enum election_status_e status;
		gchar *url = NULL;

		status = election_get_status(args->repo->election_manager,
				args->logical_name, args->logical_type, &url);
		GRID_DEBUG("Status got=%d expected=%d master=%s", status, expected, url);

		switch (status) {
			case ELECTION_LOST:
				if (pmaster && url)
					*pmaster = g_strdup(url);
				if (!(expected & ELECTION_LOST)) {
					if (expected == ELECTION_LEADER)
						err = g_error_new(gquark_log, CODE_REDIRECT, "%s", url);
					else
						err = g_error_new(gquark_log, CODE_BADOPFORSLAVE,
								"not SLAVE");
				}
				break;
			case ELECTION_LEADER:
				if (!(expected & ELECTION_LEADER))
					err = g_error_new(gquark_log, CODE_BADOPFORSLAVE, "not SLAVE");
				break;
			case ELECTION_FAILED:
				err = g_error_new(gquark_log, 500, "Election failed [%s][%s]",
						args->logical_name, args->logical_type);
				break;
		}

		if (url)
			g_free(url);
		url = NULL;
	}

	if (!err) {
		err = args->repo->cache
			? __open_maybe_cached(args, result)
			: __open_not_cached(args, result);
	}

	return err;
}


/* ------------------------------------------------------------------------- */

void
sqlx_repository_set_locator(struct sqlx_repository_s *repo,
		sqlx_file_locator_f locator, gpointer locator_data)
{
	SQLX_ASSERT(repo != NULL);
	repo->locator = locator;
	repo->locator_data = locator_data;
}

GError*
sqlx_repository_unlock_and_close(struct sqlx_sqlite3_s *sq3)
{
	GError * err=NULL;
	SQLX_ASSERT(sq3 != NULL);

	GRID_TRACE2("Closing bd=%d [%s][%s]", sq3->bd,
			sq3->logical_name, sq3->logical_type);

	if (!sq3->repo->flag_delete_on)
		sq3->deleted = FALSE;

	struct sqlx_repository_s *repo = NULL;
	gchar *n = NULL, *t = NULL;
	sqlx_repo_close_hook cb;
	gpointer cb_data = NULL;

	cb = (sq3->repo->close_callback && sqlite3_total_changes(sq3->db) > 0)
			? sq3->repo->close_callback : NULL;
	if (cb) {
		repo = sq3->repo;
		cb_data = sq3->repo->close_callback_data;
		n = g_strdup(sq3->logical_name);
		t = g_strdup(sq3->logical_type);
	}

	if (sq3->repo->cache) {
		err = sqlx_cache_unlock_and_close_base(sq3->repo->cache, sq3->bd,
			sq3->deleted);
	}
	else {
		sq3->deleted = FALSE; /* delete disabled when no cache used */
		__close_base(sq3);
	}

	if (cb) {
		cb(repo, n, t, cb_data);
		g_free(n);
		g_free(t);
	}
	return err;
}

void
sqlx_repository_unlock_and_close_noerror(struct sqlx_sqlite3_s *sq3)
{
	GError *e = sqlx_repository_unlock_and_close(sq3);
	if (e) {
		GRID_WARN("DB closure error : (%d) %s", e->code, e->message);
		g_error_free(e);
	}
}

GError*
sqlx_repository_open_and_lock(sqlx_repository_t *repo,
		const gchar *type, const gchar *name, enum sqlx_open_type_e how,
		struct sqlx_sqlite3_s **result, gchar **lead)
{
	GError *err = NULL;
	struct open_args_s args;

	if (NULL != (err = _open_fill_args(&args, repo, type, name)))
		return err;
	args.create = how & SQLX_OPEN_CREATE;

	switch (how & 0x0F) {
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

	_open_clean_args(&args);

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
sqlx_repository_status_base(sqlx_repository_t *repo,
		const gchar *type, const gchar *name)
{
	GError *err = NULL;

	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, type, name);
	SQLX_ASSERT(repo != NULL);
	SQLX_ASSERT(type != NULL);
	SQLX_ASSERT(name != NULL);

	if (NULL != (err = __get_schema(repo, type, NULL)))
		return err;

	if (!election_manager_configured(repo->election_manager)) {
		GRID_TRACE("Replication disabled by configuration, MASTER de facto");
	}
	else if (!election_has_peers(repo->election_manager, name, type)) {
		GRID_TRACE("Unable to find peers for [%s][%s]", name, type);
	}
	else {
		gchar *url = NULL;
		enum election_status_e status;

		status = election_get_status(repo->election_manager, name, type, &url);
		switch (status) {
			case ELECTION_LOST:
				err = g_error_new(gquark_log, CODE_REDIRECT, "%s", url);
				break;
			case ELECTION_LEADER:
				err = NULL;
				break;
			case ELECTION_FAILED:
				err = g_error_new(gquark_log, 500,
						"Election failed for %s.%s", name, type);
				break;
		}

		if (url)
			g_free(url);
	}

	return err;
}

GError*
sqlx_repository_prepare_election(sqlx_repository_t *repo,
		const gchar *type, const gchar *name)
{
	GError *err;

	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, type, name);
	SQLX_ASSERT(repo != NULL);
	SQLX_ASSERT(type != NULL);
	SQLX_ASSERT(name != NULL);

	if (NULL != (err = __get_schema(repo, type, NULL)))
		return err;

	if (!election_manager_configured(repo->election_manager)) {
		GRID_TRACE("Replication disabled by configuration");
		return NULL;
	}

	election_init(repo->election_manager, name, type);
	return NULL;
}

GError*
sqlx_repository_exit_election(sqlx_repository_t *repo,
		const gchar *type, const gchar *name)
{
	GError *err;

	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, type, name);
	SQLX_ASSERT(repo != NULL);
	SQLX_ASSERT(type != NULL);
	SQLX_ASSERT(name != NULL);

	if (NULL != (err = __get_schema(repo, type, NULL)))
		return err;

	if (!repo->election_manager) {
		GRID_TRACE("Replication disabled by configuration");
		return NULL;
	}

	election_exit(repo->election_manager, name, type);
	return NULL;
}

GError*
sqlx_repository_use_base(sqlx_repository_t *repo, const gchar *type,
		const gchar *name)
{
	GError *err;

	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, type, name);
	SQLX_ASSERT(repo != NULL);
	SQLX_ASSERT(type != NULL);
	SQLX_ASSERT(name != NULL);

	if (NULL != (err = __get_schema(repo, type, NULL)))
		return err;

	if (!election_manager_configured(repo->election_manager)) {
		GRID_TRACE("Replication disabled by configuration");
		return NULL;
	}

	election_start(repo->election_manager, name, type);
	return NULL;
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
		err = g_error_new(gquark_log, sqlite3_errcode(dst),
				sqlite3_errmsg(dst));
	else {
		while (SQLITE_OK == (rc = sqlite3_backup_step(backup, 1))) {}
		if (rc != SQLITE_DONE)
			err = g_error_new(gquark_log, rc, "backup error: %s",
					sqlite_strerror(rc));
		(void) sqlite3_backup_finish(backup);
	}

	GRID_TRACE("Backup %s!", err ? "failed" : "done");
	return err;
}

static GError *
fill_tmp_file(gchar *path, int *result, guint8 *raw, gsize rawsize)
{
	int fd;
	gsize wtotal;
	GError *err = NULL;

	GRID_TRACE2("%s(%s,%p,%p,%"G_GSIZE_FORMAT")", __FUNCTION__, path,
			result, raw, rawsize);

	fd = g_mkstemp(path);
	if (fd < 0)
		return g_error_new(gquark_log, errno, "mkstemp: %s", strerror(errno));

	for (wtotal=0; wtotal<rawsize ;) {
		gssize w = write(fd, raw+wtotal, rawsize-wtotal);
		if (w<0) {
			err = g_error_new(gquark_log, errno, "write: %s", strerror(errno));
			unlink(path);
			close(fd);
			return err;
		}
		wtotal += w;
	}

	*result = fd;
	return NULL;
}

static GError*
_read_file(int fd, GByteArray *gba)
{
	int rc;
	ssize_t r;
	guint8 *d;
	struct stat st;
	GError *err = NULL;

	rc = fstat(fd, &st);
	GRID_TRACE2("%s(%d,%p) size=%"G_GSIZE_FORMAT, __FUNCTION__, fd,
			gba, st.st_size);

	if (0 > rc)
		return g_error_new(gquark_log, errno, "Failed to stat the temporary base");

	g_byte_array_set_size(gba, st.st_size);
	g_byte_array_set_size(gba, 0);

	d = g_malloc(8192);

	do {
		r = read(fd, d, 8192);
		if (r < 0)
			err = g_error_new(gquark_log, errno, "read error: %s", strerror(errno));
		else if (r > 0)
			g_byte_array_append(gba, d, r);
	} while (r > 0 && !err);

	g_free(d);
	return err;
}

GError*
sqlx_repository_backup_base(struct sqlx_sqlite3_s *src_sq3,struct sqlx_sqlite3_s *dst_sq3)
{
	SQLX_ASSERT(src_sq3 != NULL);

	return  _backup_main(src_sq3->db, dst_sq3->db);
	
}

GError*
sqlx_repository_dump_base(struct sqlx_sqlite3_s *sq3, GByteArray **dump)
{
	gchar path[] = "/tmp/dump.sqlite3.XXXXXX";
	int rc, fd;
	sqlite3 *dst = NULL;
	GError *err = NULL;

	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, sq3, dump);
	SQLX_ASSERT(sq3 != NULL);
	SQLX_ASSERT(dump != NULL);

	if (0 > (fd = g_mkstemp(path)))
		return g_error_new(gquark_log, errno, "Temporary file creation error"
				" : %s", strerror(errno));

	GRID_TRACE("DUMP to [%s] fd=%d from bd=[%s][%s]", path, fd,
			sq3->logical_name, sq3->logical_type);

	/* TODO : provides a VFS dumping everything in memory */
	rc = sqlite3_open_v2(path, &dst, SQLITE_OPEN_PRIVATECACHE
			|SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE, NULL);

	if (rc != SQLITE_OK) {
		err = g_error_new(gquark_log, rc,
				"sqlite3_open error: (%s) (errno=%d) %s",
				sqlite_strerror(rc), errno, strerror(errno));
		unlink(path);
		return err;
	}

	err = _backup_main(sq3->db, dst);
	sqlite3_close(dst);
	unlink(path);

	if (!err) {
		GByteArray *_dump = g_byte_array_new();
		err = _read_file(fd, _dump);
		if (!err)
			*dump = _dump;
		else
			g_byte_array_free(_dump, TRUE);
	}

	close(fd);
	return err;
}

GError*
sqlx_repository_restore_base(struct sqlx_sqlite3_s *sq3,
		guint8 *raw, gsize rawsize)
{
	GError *err = NULL;
	gchar path[] = "/tmp/restore.sqlite3.XXXXXX";
	int rc, fd = -1;
	sqlite3 *src = NULL;

	GRID_TRACE2("%s(%p,%p,%"G_GSIZE_FORMAT")", __FUNCTION__, sq3,
			raw, rawsize);
	SQLX_ASSERT(sq3 != NULL);
	SQLX_ASSERT(raw != NULL);
	SQLX_ASSERT(rawsize > 0);

	/* fills a temporary file */
	err = fill_tmp_file(path, &fd, raw, rawsize);
	GRID_TRACE("RESTORE from [%s] fd=%d in [%s][%s]", path, fd,
			sq3->logical_name, sq3->logical_type);

	if (err != NULL) {
		SQLX_ASSERT(fd < 0);
		g_prefix_error(&err, "Temporary file error: ");
	}
	else {
		SQLX_ASSERT(fd >= 0);

		/* Tries to open the temporary file as a SQLite3 DB */
		rc = sqlite3_open_v2(path, &src, SQLITE_OPEN_READONLY, NULL);
		if (rc != SQLITE_OK && rc != SQLITE_DONE) {
			err = g_error_new(gquark_log, rc,
					"sqlite3_open error: (%s) (errno=%d) %s",
					sqlite_strerror(rc), errno, strerror(errno));
			g_prefix_error(&err, "Invalid raw SQLite base: ");
		}
		else { /* Backup now! */
			err = _backup_main(src, sq3->db);
			sqlite3_close(src);
			version_load(sq3, TRUE);
		}

		unlink(path);
		close(fd);
	}

	GRID_TRACE("Base restored ? (%d) %s", err?err->code:0,
			err?err->message:"OK");
	return err;
}

GError*
sqlx_repository_retore_from_master(struct sqlx_sqlite3_s *sq3)
{
	SQLX_ASSERT(sq3 != NULL);

	return !election_manager_configured(sq3->repo->election_manager)
		? g_error_new(gquark_log, 500, "Replication not configured")
		: election_manager_trigger_RESYNC(sq3->repo->election_manager,
			sq3->logical_name, sq3->logical_type);
}


/* ------------------------------------------------------------------------- */

GError*
sqlx_repository_get_handle(sqlx_repository_t *repo, gint bd,
		struct sqlx_sqlite3_s **result)
{
	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	GRID_TRACE2("%s(%p,%d,%p)", __FUNCTION__, repo, bd, result);
	SQLX_ASSERT(repo != NULL);
	SQLX_ASSERT(bd >= 0);
	SQLX_ASSERT(result != NULL);

	*result = sqlx_cache_get_handle(repo->cache, bd);
	return NULL;
}

GError *
sqlx_repository_get_version(struct sqlx_sqlite3_s *sq3, GTree **result)
{
	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, sq3, result);
	SQLX_ASSERT(sq3 != NULL);
	SQLX_ASSERT(result != NULL);

	*result = version_dup(sq3->versions);
	return NULL;
}

GError *
sqlx_repository_get_version2(sqlx_repository_t *repo,
		const gchar *type, const gchar *name, GTree **result)
{
	GError *err;
	GTree *version = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	SQLX_ASSERT(repo != NULL);
	SQLX_ASSERT(type != NULL);
	SQLX_ASSERT(name != NULL);
	SQLX_ASSERT(result != NULL);

	err = sqlx_repository_open_and_lock(repo, type, name,
			SQLX_OPEN_LOCAL, &sq3, NULL);

	if (!err) {
		err = sqlx_repository_get_version(sq3, &version);
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	if (!err) {
		SQLX_ASSERT(version != NULL);
		*result = version;
		return NULL;
	}

	return err;
}

guint
sqlx_repository_expire_bases(sqlx_repository_t *repo, guint max,
		GTimeVal *pivot, GTimeVal *end)
{
	GRID_TRACE2("%s(%p,%u,%p,%p)", __FUNCTION__, repo, max, pivot, end);

	if (!repo || !repo->cache)
		return 0;
	return sqlx_cache_expire(repo->cache, max, pivot, end);
}

guint
sqlx_repository_retry_elections(sqlx_repository_t *repo, guint max,
		GTimeVal *pivot, GTimeVal *end)
{
	if (!repo || !repo->cache || !election_manager_configured(repo->election_manager))
		return 0;

	return election_manager_retry_elections(repo->election_manager,
			max, pivot, end);
}

void
sqlx_repository_exit_elections(sqlx_repository_t *repo, GTimeVal *max)
{
	if (repo && election_manager_configured(repo->election_manager))
		election_manager_exit_all(repo->election_manager, max);
}

GError*
sqlx_repository_configure_replication(sqlx_repository_t *repo,
		struct replication_config_s *config)
{
	GError *err;

	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, repo, config);
	SQLX_ASSERT(repo != NULL);
	SQLX_ASSERT(repo->election_manager == NULL);
	CONFIG_CHECK(config);

	err = election_manager_create(config, repo, &(repo->election_manager));
	if (err) {
		g_prefix_error(&err, "Election manager init failure: ");
		return err;
	}

	return NULL;
}

GError*
sqlx_repository_clients_round(sqlx_repository_t *repo, time_t max)
{
	SQLX_ASSERT(repo != NULL);
	return sqlx_repository_replication_configured(repo)
		? election_manager_clients_round(repo->election_manager, max)
		: NULL;
}

void
sqlx_repository_whatabout(sqlx_repository_t *r, const gchar *type,
		const gchar *name, gchar *d, gsize ds)
{
	SQLX_ASSERT(r != NULL);

	if (!r->election_manager) {
		static const gchar msg[] = "No replication";
		g_strlcpy(d, msg, ds-1);
		d[sizeof(msg)-1] = '\0';
		return ;
	}

	election_manager_whatabout(r->election_manager, name, type, d, ds);
}

gboolean
sqlx_repository_replication_configured(const struct sqlx_repository_s *r)
{
	return (r != NULL) && election_manager_configured(r->election_manager);
}

struct election_manager_s*
sqlx_repository_get_elections_manager(struct sqlx_repository_s *r)
{
	SQLX_ASSERT(r != NULL);
	return r->election_manager;
}

