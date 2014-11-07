#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqliterepo"
#endif

#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sqlite3.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "sqliterepo.h"
#include "hash.h"
#include "cache.h"
#include "election.h"
#include "version.h"
#include "sqlite_utils.h"
#include "internals.h"
#include "restoration.h"

#define GSTR_APPEND_SEP(S) do { \
	if ((S)->str[(S)->len-1]!=G_DIR_SEPARATOR) \
			g_string_append_c((S), G_DIR_SEPARATOR); \
} while (0)

static inline gboolean
election_manager_configured(const struct election_manager_s *em)
{
	const struct replication_config_s *cfg;
	return (em != NULL)
		&& ((cfg = election_manager_get_config(em)) != NULL)
		&& (cfg->mode != ELECTION_MODE_NONE);
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


/* ------------------------------------------------------------------------- */


static void
_admin_entry_set_str_noerror(sqlite3 *db, const gchar *k, const gchar *v)
{
	GError *e = sqlite_admin_entry_set(db, 1, k, (guint8*)v, strlen(v));
	if (e) {
		GRID_WARN("SQLX failed to set admin [%s] to [%s]", k, v);
		g_clear_error(&e);
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

	sqlx_repository_call_close_callback(sq3);

	/* delete the base */
	if (sq3->deleted) {
		if (sq3->repo->election_manager) {
			GError *err = election_exit(sq3->repo->election_manager,
					sq3->logical_name,
					sq3->logical_type);
			if (err) {
				GRID_WARN("Failed to exit election [%s]", err->message);
				g_clear_error(&err);
			} else {
				GRID_TRACE("exit election succeeded [%s][%s]",
						sq3->logical_name,
						sq3->logical_type);
			}
		}
		__delete_base(sq3);
	}

	if (sq3->db)
		_close_handle(&(sq3->db));

	/* Clean the structure */

	if (sq3->logical_name)
		g_free(sq3->logical_name);
	if (sq3->logical_type)
		g_free(sq3->logical_type);
	if (sq3->path)
		g_free(sq3->path);
	if (sq3->admin)
		g_tree_destroy(sq3->admin);

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
	int flags = SQLITE_OPEN_NOMUTEX|SQLITE_OPEN_READWRITE|SQLITE_OPEN_CREATE;
	rc = sqlite3_open_v2(tmp_path, &db, flags, NULL);
	if (rc != SQLITE_OK) {
		_close_handle(&db);
		error = NEWERROR(rc, "SQLite error [%s]: (%d) %s",
				tmp_path, rc, sqlite3_errmsg(db));
		goto label_exit;
	}

	/* Force an admin table */
	rc = sqlite3_exec(db, "CREATE TABLE admin ("
				"k TEXT PRIMARY KEY NOT NULL, v BLOB DEFAULT NULL)",
				NULL, NULL, &errmsg);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)  {
		error = NEWERROR(rc, "Admin table error : %s (%s)",
			sqlite3_errmsg(db), errmsg);
		goto label_exit;
	}

	if (version && *version)
		_admin_entry_set_str_noerror(db, "schema_version", version);

	/* Apply the schema in it */
	if ((schema != NULL)&&(strlen(schema) > 0)) {
		rc = sqlite3_exec(db, schema, NULL, NULL, &errmsg);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)  {
			error = NEWERROR(rc, "Schema error : %s (%s)",
				sqlite3_errmsg(db), errmsg);
			goto label_exit;
		}
	}

	_close_handle(&db);
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
			? (NEWERROR(EINVAL, "Unmanaged schema type [%s] [%s]", hashstr_str(ht), type))
			: (NEWERROR(EINVAL, "Unmanaged schema type [%s]", hashstr_str(ht)));

	if (res)
		*res = raw;
	return NULL;
}


/* ------------------------------------------------------------------------- */


GError *
sqlx_repository_init(const gchar *vol, const struct sqlx_repo_config_s *cfg,
		sqlx_repository_t **result)
{
	struct stat s;
	sqlx_repository_t *repo;

	(void) sqlite3_initialize();

	if (!sqlite3_threadsafe())
		return NEWERROR(0, "SQLite not in safe mode");

	if (cfg && cfg->flags & SQLX_REPO_NOCACHE) {
		// if there are several connections on the same base, we will use a
		// shared cache that wil prevent us of too many I/O operations.
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

	/* Lock the volume with XATTR */
	if (cfg != NULL) {
		if (!(cfg->flags & SQLX_REPO_NOLOCK)) {
			GError *err = volume_service_lock(vol, cfg->lock.type,
						cfg->lock.srv, cfg->lock.ns);
			if (err != NULL)
				return err;
		}
	}

	repo = g_malloc0(sizeof(struct sqlx_repository_s));
	g_strlcpy(repo->basedir, vol, sizeof(repo->basedir)-1);
	repo->hash_depth = 2;
	repo->hash_width = 2;

	repo->schemas = g_hash_table_new_full(
			(GHashFunc)hashstr_hash, (GEqualFunc)hashstr_equal,
			g_free, __clean_schema);

	repo->flag_autocreate = !cfg ? TRUE : BOOL(cfg->flags & SQLX_REPO_AUTOCREATE);
	repo->flag_autovacuum = !cfg ? FALSE : BOOL(cfg->flags & SQLX_REPO_VACUUM);
	repo->flag_delete_on = !cfg ? FALSE : BOOL(cfg->flags & SQLX_REPO_DELETEON);

	if (!cfg || !(cfg->flags & SQLX_REPO_NOCACHE)) {
		repo->cache = sqlx_cache_init();
		sqlx_cache_set_close_hook(repo->cache,
				(sqlx_cache_close_hook)__close_base);
	}

	if (cfg) {
		repo->sync_mode_solo = cfg->sync_solo;
		repo->sync_mode_repli = cfg->sync_repli;
	} else {
		repo->sync_mode_solo = SQLX_SYNC_NORMAL;
		repo->sync_mode_repli = SQLX_SYNC_NORMAL;
	}

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
		g_hash_table_destroy(repo->schemas);

	memset(repo, 0, sizeof(*repo));
	g_free(repo);

	int rc;
	do {
		rc = sqlite3_release_memory(1024 * 1024);
	} while (rc > 0);
}

void
sqlx_repository_configure_hash(sqlx_repository_t *repo,
		guint width, guint depth)
{
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(repo->running);

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
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(repo->running);
	EXTRA_ASSERT(repo->bases_count == 0);

	GRID_TRACE2("%s(%p,%u)", __FUNCTION__, repo, max);
	g_assert(max >= 4);

	if (repo->cache)
		sqlx_cache_set_max_bases(repo->cache, max);
	repo->bases_count = 0;
	repo->bases_max = max;
}

GError*
sqlx_repository_configure_type(sqlx_repository_t *repo,
		const gchar *type, const gchar *version, const gchar *schema)
{
	GByteArray *raw = NULL;
	GError *error = NULL;

	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(repo->running);
	EXTRA_ASSERT(type != NULL);
	EXTRA_ASSERT(schema != NULL);

	if (NULL != (error = __test_schema(schema, version, &raw)))
		return error;

	g_hash_table_insert(repo->schemas, hashstr_create(type), raw);
	GRID_INFO("Schema configured for type [%s]", type);
	GRID_DEBUG("Schema [%s] : %s", type, schema);
	return NULL;
}

void
sqlx_repository_configure_open_timeout(sqlx_repository_t *repo,
		gint64 timeout)
{
	struct sqlx_cache_s *cache = sqlx_repository_get_cache(repo);
	if (cache) {
		sqlx_cache_set_open_timeout(cache, (glong)timeout);
	} else {
		GRID_INFO("Not setting open timeout since there is no cache");
	}
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
	const gchar* url = NULL;

    struct election_manager_s* em = sqlx_repository_get_elections_manager(repo);
    if (em) {
        const struct replication_config_s *emrc = election_manager_get_config(em);
        if (emrc) {
            url = emrc->get_local_url(emrc->ctx);
            GRID_DEBUG("%s: url:[%s]", __FUNCTION__, url);
        }
    }
	return url;
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

	gboolean create : 1;
	gboolean no_refcheck : 1;
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
				return NEWERROR(errno, "open(O_CREAT|O_EXCL) error : %d (%s)",
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
			metautils_pclose(&fd);
			return NEWERROR(errsav, "write() error : %d (%s)",
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
			_admin_entry_set_str_noerror(h, "base_name", args->logical_name);
			_admin_entry_set_str_noerror(h, "container_name", args->logical_name);
			_admin_entry_set_str_noerror(h, "base_type", args->logical_type);
			sqlx_exec(h, "COMMIT");
			sqlite3_close(h);
		}
	} while (0);

	metautils_pclose(&fd);
	return NULL;
}

static GError *
_open_fill_args(struct open_args_s *args, struct sqlx_repository_s *repo,
		const gchar *t, const gchar *n)
{
	memset(args, 0, sizeof(struct open_args_s));

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

	return __get_schema(repo, t, &(args->raw));
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

static void
__admin_ensure_version(struct sqlx_sqlite3_s *sq3)
{
	sqlite3_stmt *stmt = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db, "SELECT name FROM sqlite_master"
			" WHERE type = 'table'", -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		EXTRA_ASSERT(stmt != NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			const gchar *name = (const gchar*)sqlite3_column_text(stmt, 0);
			gchar *k = g_strdup_printf("version:main.%s", name);
			if (g_tree_lookup(sq3->admin, k))
				g_free(k);
			else {
				_admin_entry_set_str_noerror(sq3->db, k, "1:0");
				g_tree_replace(sq3->admin, k, metautils_gba_from_string("1:0"));
			}
		}
		sqlite3_finalize(stmt);
	}
}

static void
__admin_load_from_table(struct sqlx_sqlite3_s *sq3)
{
	sqlite3_stmt *stmt = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db, "SELECT k,v FROM admin", -1, &stmt, NULL);
	if (rc == SQLITE_OK) {
		EXTRA_ASSERT(stmt != NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			const gchar *k = (const gchar*)sqlite3_column_text(stmt, 0);
			GByteArray *v = g_byte_array_append(g_byte_array_new(),
					sqlite3_column_blob(stmt, 1),
					sqlite3_column_bytes(stmt, 1));
			g_tree_replace(sq3->admin, g_strdup(k), v);
		}
		sqlite3_finalize(stmt);
	}
}

void
sqlx_admin_reload(struct sqlx_sqlite3_s *sq3)
{
	if (sq3->admin)
		g_tree_destroy(sq3->admin);
	sq3->admin = g_tree_new_full(metautils_strcmp3, NULL,
			g_free, metautils_gba_unref);
	__admin_load_from_table(sq3);
	__admin_ensure_version(sq3);
	GRID_TRACE("Loaded %u ADMIN from [%s.%s]", g_tree_nnodes(sq3->admin),
			sq3->logical_name, sq3->logical_type);
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
	handle = NULL;

	switch (rc = sqlite3_open_v2(args->realpath, &handle, flags, NULL)) {
		case SQLITE_OK:
		case SQLITE_DONE:
			GRID_TRACE2("Open succeeded [%s]", args->realpath);
			break;
		case SQLITE_NOTFOUND:
		case SQLITE_CANTOPEN:
			GRID_DEBUG("Open soft error [%s] : (%d) %s", args->realpath,
					rc, sqlite_strerror(rc));
			if (attempts-- && (args->create || args->repo->flag_autocreate)) {
				_close_handle(&handle);
				if (!(error = __create_base(args, args->realpath, args->raw))) {
					GRID_TRACE("Base created, retrying open [%s]", args->realpath);
					goto retry;
				}
				GRID_DEBUG("DB creation error on [%s] : (%d) %s",
						args->realpath, error->code, error->message);
			}
			else {
		default:
				_close_handle(&handle);
				GRID_DEBUG("Open strong error [%s] : (%d) %s",
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

	/* Lazy DB config */
	sqlite3_busy_timeout(handle, 30000);
	if (args->is_replicated) {
		sqlx_exec(handle, "PRAGMA journal_mode = MEMORY");
		sqlx_exec(handle, _get_pragma_sync(args->repo->sync_mode_repli));
	} else {
		GRID_TRACE("Using DELETE journal mode for base [%s]", args->realpath);
		sqlx_exec(handle, _get_pragma_sync(args->repo->sync_mode_solo));
	}
	sqlx_exec(handle, "PRAGMA foreign_keys = OFF");
	sqlx_exec(handle, "BEGIN");

	sq3 = g_malloc0(sizeof(*sq3));
	sq3->db = handle;
	sq3->bd = -1;
	sq3->repo = args->repo;
	sq3->config = election_manager_get_config(args->repo->election_manager);
	sq3->logical_name = g_strdup(args->logical_name);
	sq3->logical_type = g_strdup(args->logical_type);
	sq3->path = g_strdup(args->realpath);

	sqlx_admin_reload(sq3);

	sqlx_exec(handle, "COMMIT");

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
	GRID_TRACE("Cache slot reserved bd=%d, base [%s][%s] %s open",
				bd, args->logical_name, args->logical_type,
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

	gboolean election_configured = election_manager_configured(
			args->repo->election_manager);

	if (election_configured && !args->no_refcheck) {
		gboolean has_peers = FALSE;
		err = election_has_peers(args->repo->election_manager,
				args->logical_name, args->logical_type, &has_peers);
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
				expected, args->logical_name, args->logical_type,
				args->is_replicated ? "true" : "false");
	}
	else {
		enum election_status_e status;
		gchar *url = NULL;

		status = election_get_status(args->repo->election_manager,
				args->logical_name, args->logical_type, &url);
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
				err = NEWERROR(500, "Election failed [%s][%s]",
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

GError*
sqlx_repository_unlock_and_close2(struct sqlx_sqlite3_s *sq3, guint32 flags)
{
	GError * err=NULL;
	EXTRA_ASSERT(sq3 != NULL);

	GRID_TRACE2("Closing bd=%d [%s][%s]", sq3->bd,
			sq3->logical_name, sq3->logical_type);

	if (!sq3->repo->flag_delete_on)
		sq3->deleted = FALSE;

	if (sq3->repo->cache) {
		err = sqlx_cache_unlock_and_close_base(sq3->repo->cache, sq3->bd,
			sq3->deleted || (flags & SQLX_CLOSE_IMMEDIATELY));
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
		GRID_WARN("DB closure error : (%d) %s", e->code, e->message);
		g_error_free(e);
	}
}

void
sqlx_repository_unlock_and_close_noerror(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_repository_unlock_and_close_noerror2(sq3, 0);
}

GError*
sqlx_repository_open_and_lock(sqlx_repository_t *repo,
		const gchar *type, const gchar *name, enum sqlx_open_type_e how,
		struct sqlx_sqlite3_s **result, gchar **lead)
{
	GError *err = NULL;
	struct open_args_s args;

	memset(&args, '\0', sizeof(struct open_args_s));

	EXTRA_ASSERT(repo != NULL);
	if (result)
		*result = NULL;

	if (!repo->running)
		return NEWERROR(500, "Repository being closed");

	if (NULL != (err = _open_fill_args(&args, repo, type, name)))
		return err;
	args.no_refcheck = BOOL(how & SQLX_OPEN_NOREFCHECK);
	args.create = BOOL(how & SQLX_OPEN_CREATE);

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
sqlx_repository_has_base2(sqlx_repository_t *repo, const gchar *type,
		const gchar *name, gchar** bddname)
{
	struct open_args_s args;

	if (bddname != NULL)
		*bddname = NULL;

	GError *err = _open_fill_args(&args, repo, type, name);
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
		const gchar *type, const gchar *name)
{
	GError *err = NULL;
	gboolean has_peers = FALSE;

	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, type, name);
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(type != NULL);
	EXTRA_ASSERT(name != NULL);

	if (!repo->running)
		return NEWERROR(500, "Repository being shut down");

	if (NULL != (err = __get_schema(repo, type, NULL)))
		return err;

	if (!election_manager_configured(repo->election_manager)) {
		GRID_TRACE("Replication disabled by configuration, MASTER de facto");
		return NULL;
	}

	err = election_has_peers(repo->election_manager, name, type, &has_peers);
	if (err != NULL) {
		g_prefix_error(&err, "Peers resolution error: ");
		return err;
	}

	if (!has_peers) {
		GRID_TRACE("Unable to find peers for [%s][%s]", name, type);
		return NULL;
	}

	gchar *url = NULL;
	enum election_status_e status;

	status = election_get_status(repo->election_manager, name, type, &url);
	switch (status) {
		case ELECTION_LOST:
			if (GRID_DEBUG_ENABLED()) {
				gchar **my_peers = NULL;
				gboolean master_in_peers = FALSE;
				GError *err2 = election_get_peers(repo->election_manager,
						name, type, &my_peers);
				for (gchar **cursor = my_peers;
						cursor && *cursor && !master_in_peers;
						cursor++) {
					master_in_peers |= (0 == g_strcmp0(url, *cursor));
				}
				if (!master_in_peers) {
					gchar *tmp = g_strjoinv(", ", my_peers);
					GRID_DEBUG("Redirecting to a bad service (%s not in [%s])",
							url, tmp);
					g_free(tmp);
				}
				g_strfreev(my_peers);
				g_clear_error(&err2);
			}
			err = NEWERROR(CODE_REDIRECT, "%s", url);
			break;
		case ELECTION_LEADER:
			err = NULL;
			break;
		case ELECTION_FAILED:
			err = NEWERROR(500,
					"Election failed for %s.%s", name, type);
			break;
	}

	if (url)
		g_free(url);
	return err;
}

GError*
sqlx_repository_prepare_election(sqlx_repository_t *repo,
		const gchar *type, const gchar *name)
{
	GError *err;

	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, type, name);
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(type != NULL);
	EXTRA_ASSERT(name != NULL);

	if (!repo->running)
		return NEWERROR(500, "Repository being shut down");

	if (NULL != (err = __get_schema(repo, type, NULL)))
		return err;

	if (!election_manager_configured(repo->election_manager)) {
		GRID_TRACE("Replication disabled by configuration");
		return NULL;
	}

	return election_init(repo->election_manager, name, type);
}

GError*
sqlx_repository_exit_election(sqlx_repository_t *repo,
		const gchar *type, const gchar *name)
{
	GError *err;

	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, type, name);
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(type != NULL);
	EXTRA_ASSERT(name != NULL);

	if (!repo->running)
		return NEWERROR(500, "Repository being shut down");

	if (NULL != (err = __get_schema(repo, type, NULL)))
		return err;

	if (!repo->election_manager) {
		GRID_TRACE("Replication disabled by configuration");
		return NULL;
	}

	err = election_exit(repo->election_manager, name, type);
	return err;
}

GError*
sqlx_repository_use_base(sqlx_repository_t *repo, const gchar *type,
		const gchar *name)
{
	GError *err;

	GRID_TRACE2("%s(%p,t=%s,n=%s)", __FUNCTION__, repo, type, name);
	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(type != NULL);
	EXTRA_ASSERT(name != NULL);

	if (!repo->running)
		return NEWERROR(500, "Repository being shut down");

	if (NULL != (err = __get_schema(repo, type, NULL)))
		return err;

	if (!election_manager_configured(repo->election_manager)) {
		GRID_TRACE("Replication disabled by configuration");
		return NULL;
	}

	return election_start(repo->election_manager, name, type);
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
		err = NEWERROR(sqlite3_errcode(dst),
				sqlite3_errmsg(dst));
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
	GRID_TRACE2("%s(%d,%p) size=%"G_GSIZE_FORMAT, __FUNCTION__, fd,
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
	gchar path[] = "/tmp/dump.sqlite3.XXXXXX";
	int rc, fd;
	sqlite3 *dst = NULL;
	GError *err = NULL;

	GRID_TRACE2("%s(%p,%p,%p)", __FUNCTION__, sq3, read_file_cb, cb_arg);
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(read_file_cb != NULL);

	if (0 > (fd = g_mkstemp(path)))
		return NEWERROR(errno, "Temporary file creation error"
				" : %s", strerror(errno));

	GRID_TRACE("DUMP to [%s] fd=%d from bd=[%s][%s]", path, fd,
			sq3->logical_name, sq3->logical_type);

	/* TODO : provides a VFS dumping everything in memory */
	rc = sqlite3_open_v2(path, &dst, SQLITE_OPEN_PRIVATECACHE
			|SQLITE_OPEN_CREATE|SQLITE_OPEN_READWRITE, NULL);

	if (rc != SQLITE_OK) {
		_close_handle(&dst);
		err = NEWERROR(rc,
				"sqlite3_open error: (%s) (errno=%d) %s",
				sqlite_strerror(rc), errno, strerror(errno));
		unlink(path);
		return err;
	}

	err = _backup_main(sq3->db, dst);
	_close_handle(&dst);
	unlink(path);

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
		GByteArray *_dump = g_byte_array_new();
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
			GByteArray *gba = g_byte_array_new();
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
sqlx_repository_restore_base(struct sqlx_sqlite3_s *sq3,
		guint8 *raw, gsize rawsize)
{
	GError *err = NULL;
	struct restore_ctx_s *restore_ctx = NULL;

	GRID_TRACE2("%s(%p,%p,%"G_GSIZE_FORMAT")", __FUNCTION__, sq3,
			raw, rawsize);
	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(raw != NULL);
	EXTRA_ASSERT(rawsize > 0);

	/* fills a temporary file */
	err = restore_ctx_create("/tmp/restore.sqlite3.XXXXXX", &restore_ctx);
	if (err != NULL) {
		g_prefix_error(&err, "Failed to create restore context: ");
	} else {
		err = restore_ctx_append(restore_ctx, raw, rawsize);
		if (err != NULL) {
			g_prefix_error(&err, "Failed to fill temp file: ");
		} else {
			EXTRA_ASSERT(restore_ctx->fd >= 0);
			err = sqlx_repository_restore_from_file(sq3, restore_ctx->path);
		}
		restore_ctx_clear(&restore_ctx);
	}

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

	return !election_manager_configured(sq3->repo->election_manager)
		? NEWERROR(500, "Replication not configured")
		: election_manager_trigger_RESYNC(sq3->repo->election_manager,
			sq3->logical_name, sq3->logical_type);
}

GError *
sqlx_repository_get_version(struct sqlx_sqlite3_s *sq3, GTree **result)
{
	GRID_TRACE2("%s(%p,%p)", __FUNCTION__, sq3, result);
	if (!sq3 || !result)
		return NEWERROR(500, "Invalid parameter");
	*result = version_extract_from_admin(sq3);
	return NULL;
}

GError *
sqlx_repository_get_version2(sqlx_repository_t *repo,
		const gchar *type, const gchar *name, GTree **result)
{
	GRID_TRACE2("%s(%p,%s,%s)", __FUNCTION__, repo, type, name);

	GError *err;
	GTree *version = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(repo != NULL);
	EXTRA_ASSERT(type != NULL);
	EXTRA_ASSERT(name != NULL);
	EXTRA_ASSERT(result != NULL);

	*result = NULL;
	err = sqlx_repository_open_and_lock(repo, type, name,
			SQLX_OPEN_LOCAL, &sq3, NULL);
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

