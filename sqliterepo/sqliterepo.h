/**
 * @file sqliterepo.h
 */

#ifndef SQLX__H
# define SQLX__H 1

/**
 * @defgroup sqliterepo_repo Repository of bases
 * @ingroup sqliterepo
 * @brief
 * @details
 *
 * @{
 */

# include <unistd.h>
# include <sqlite3.h>
# include <metautils/lib/metautils.h>
# include <sqliterepo/sqlite_utils.h>

struct hashstr_s;
struct replication_config_s;
struct election_manager_s;

struct sqlx_cache_s;
struct sqlx_repctx_s;
struct sqlx_sqlite3_s;

typedef struct sqlx_repository_s sqlx_repository_t;

typedef void (*sqlx_repo_close_hook)(struct sqlx_sqlite3_s *sq3,
		gboolean deleted, gpointer cb_data);

typedef GError* (*sqlx_repo_open_hook)(struct sqlx_sqlite3_s *sq3,
		gpointer cb_data);

typedef void (*sqlx_repo_change_hook)(struct sqlx_sqlite3_s *sq3,
		gpointer cb_data);

/**
 * @param locator_data
 * @param base_name
 * @param base_type
 * @param file_name
 */
typedef void (*sqlx_file_locator_f) (gpointer locator_data,
		const gchar *base_name, const gchar *base_type,
		GString *file_name);

/**
 *
 */
struct sqlx_sqlite3_s
{
	struct sqlx_repository_s *repo;
	const struct replication_config_s *config;
	sqlite3 *db;
	gchar *logical_name;
	gchar *logical_type;
	gchar *path;

	GTree *admin; // <gchar*,GByteArray*>
	gint bd; // ID in cache
	gboolean deleted : 8;
	gboolean no_peers : 8; // Prevent get_peers()
};

enum sqlx_repo_flag_e
{
	SQLX_REPO_NOCACHE      = 0x01,
	SQLX_REPO_VACUUM       = 0x02,
	SQLX_REPO_DELETEON     = 0x04,
	SQLX_REPO_NOLOCK       = 0x08,
	SQLX_REPO_AUTOCREATE   = 0x10,
};

enum sqlx_sync_mode_e
{
	SQLX_SYNC_OFF=0,
	SQLX_SYNC_NORMAL=1,
	SQLX_SYNC_FULL=2
};

struct sqlx_repo_config_s
{
	enum sqlx_repo_flag_e flags; /**< several options. */

	enum sqlx_sync_mode_e sync_solo; /**< Which value for pragma synchronous'
									   for not replicated bases */

	enum sqlx_sync_mode_e sync_repli; /**< Which value for pragma synchronous'
									   for replicated bases */
	struct {
		const gchar *ns; /**< The name of the physical NS of the repository */
		const gchar *type; /**< The service type used for locking */
		const gchar *srv; /**< a unique ID for the service, i.e. its service
						   * IP:PORT */
	} lock;
};

/* ------------------------------------------------------------------------- */

/** Constructor for repository structures.
 *
 * A new repository has no replication configured by default.
 *
 * @param vol the volume underlying the repository
 * @param cfg may be NULL (so default values are considered), or specifies
 *            configuration triggers on the init step.
 * @param result a placeholder for the repository to be created
 * @return NULL in case of success or a pointer to a valid GError that
 * describes the error
 */
GError * sqlx_repository_init(const gchar *vol,
		const struct sqlx_repo_config_s *cfg,
		sqlx_repository_t **result);

/** Cleans all the structures associated with the given repository.
 * For security purposes, it internally calls sqlx_repository_stop(). */
void sqlx_repository_clean(sqlx_repository_t *repo);



struct sqlx_cache_s* sqlx_repository_get_cache(struct sqlx_repository_s *r);

struct election_manager_s* sqlx_repository_get_elections_manager(
		struct sqlx_repository_s *repo);

const gchar* sqlx_repository_get_local_addr(struct sqlx_repository_s *repo);

gboolean sqlx_repository_replication_configured(
		const struct sqlx_repository_s *r);

gboolean sqlx_repository_running(sqlx_repository_t *repo);



/** Mark the repository and its internal structures as being shut down.
 * This prevents potential background threads to still manage messages,
 * allocate memory, open bases, etc. Can be safely called several times. */
void sqlx_repository_stop(sqlx_repository_t *repo);

/** Give to the repository the way to compute real paths */
void sqlx_repository_set_locator(struct sqlx_repository_s *repo,
		sqlx_file_locator_f locator, gpointer locator_data);

/** Associate an election manager to the repository. The manager isn't owned
 * by the repository, and won't be freed at exit. */
void sqlx_repository_set_elections(sqlx_repository_t *repo,
		struct election_manager_s *manager);

/** Tells how to perform the directory-based hash on the base's name. */
void sqlx_repository_configure_hash(sqlx_repository_t *repo,
		guint width, guint depth);

/** Calling this function on a repository that already managed a base has no
 * effect. */
void sqlx_repository_configure_maxbases(sqlx_repository_t *repo,
		guint max);

/** Register a new DB type with its schema.  */
GError* sqlx_repository_configure_type(sqlx_repository_t *repo,
		const gchar *type, const gchar *version, const gchar *schema);

/**
 * Set open timeout for bases currently in use by another thread.
 *
 * @param timeout milliseconds
 */
void sqlx_repository_configure_open_timeout(sqlx_repository_t *repo,
		gint64 timeout);

/**
 */
void sqlx_repository_configure_close_callback(sqlx_repository_t *repo,
		sqlx_repo_close_hook cb, gpointer cb_data);

/**
 */
void sqlx_repository_call_close_callback(struct sqlx_sqlite3_s *sq3);

/**
 */
void sqlx_repository_configure_open_callback(sqlx_repository_t *repo,
		sqlx_repo_open_hook cb, gpointer cb_data);

/**
 */
void sqlx_repository_configure_change_callback(sqlx_repository_t *repo,
		sqlx_repo_change_hook cb, gpointer cb_data);

/**
 */
void sqlx_repository_call_change_callback(struct sqlx_sqlite3_s *sq3);


/* Bases operations -------------------------------------------------------- */

enum sqlx_open_type_e
{
	SQLX_OPEN_LOCAL       = 0x00,
	SQLX_OPEN_MASTERONLY  = 0x01,
	SQLX_OPEN_SLAVEONLY   = 0x02,
	SQLX_OPEN_MASTERSLAVE = 0x03,
#define SQLX_OPEN_REPLIMODE 0x0F
	SQLX_OPEN_CREATE      = 0x10,
	SQLX_OPEN_NOREFCHECK  = 0x20
};

enum sqlx_close_flag_e
{
	/** Close the base immediately, don't keep it in the cache */
	SQLX_CLOSE_IMMEDIATELY = 0x01,
};

/**
 * @param repo
 * @param type
 * @param name
 * @param how
 * @param sq3
 * @param lead
 * @return
 */
GError* sqlx_repository_open_and_lock(sqlx_repository_t *repo,
		const gchar *type, const gchar *name, enum sqlx_open_type_e how,
		struct sqlx_sqlite3_s **sq3, gchar **lead);

/**
 * @param sq3
 * @return
 */
GError* sqlx_repository_unlock_and_close(struct sqlx_sqlite3_s *sq3);

/**
 * @param sq3
 * @param flags OR'ed close flags (see sqlx_close_flag_e)
 */
GError* sqlx_repository_unlock_and_close2(struct sqlx_sqlite3_s *sq3,
		guint32 flags);

/**
 * @param sq3
 * @see sqlx_repository_unlock_and_close()
 */
void sqlx_repository_unlock_and_close_noerror(struct sqlx_sqlite3_s *sq3);

/**
 * @param sq3
 * @param flags flags OR'ed close flags (see sqlx_close_flag_e)
 */
void sqlx_repository_unlock_and_close_noerror2(struct sqlx_sqlite3_s *sq3,
		guint32 flags);

/**
 */
GError * sqlx_repository_get_version(struct sqlx_sqlite3_s *sq3,
		GTree **result);

/** Opens the base (locally) then calls sqlx_repository_get_version() before
 * closing it.  */
GError * sqlx_repository_get_version2(sqlx_repository_t *repo,
		const gchar *type, const gchar *name, GTree **result);

/**
 */
GError* sqlx_repository_has_base2(sqlx_repository_t *repo, const gchar *type,
        const gchar *name,  gchar** bddname);

#define sqlx_repository_has_base(r,t,n) sqlx_repository_has_base2(r,t,n,NULL)

/** Allocates the internal structure for an election, but does not
 * kick it off.  */
GError* sqlx_repository_prepare_election(sqlx_repository_t *repo,
		const gchar *type, const gchar *name);

GError* sqlx_repository_exit_election(sqlx_repository_t *repo,
		const gchar *type, const gchar *name);

/** Triggers the global election mechanism on a base given its name
 */
GError* sqlx_repository_use_base(sqlx_repository_t *repo,
		const gchar *type, const gchar *name);

/** Triggers the global election mechanism on a base given its name and
 * returns when a final status (or a timeout) has been reached.
 * @return NULL if master, an error with code 303 if slave, an error with
 *         another code if the election failed.
 */
GError* sqlx_repository_status_base(sqlx_repository_t *repo,
		const gchar *type, const gchar *name);

/** Collect into a buffer the binary dump of the base (i.e. the content
 *  of a valid sqlite3 file, with only the meaningful pages). */
GError* sqlx_repository_dump_base_gba(struct sqlx_sqlite3_s *sq3,
		GByteArray **dump);

/** Callback for sqlx_repository_dump_base_fd(). */
typedef GError*(*dump_base_fd_cb)(int fd, gpointer arg);

/** Open a dump of the base (with only the meaningful pages)
 *  and pass the file descriptor to a callback. */
GError* sqlx_repository_dump_base_fd(struct sqlx_sqlite3_s *sq3,
		dump_base_fd_cb callback, gpointer callback_arg);

/** Callback for sqlx_repository_dump_base_chunked() */
typedef GError*(*dump_base_chunked_cb)(GByteArray *gba, gint64 remaining_bytes,
		gpointer arg);

/** Open a dump of the base (with only the meaningful pages),
 *  and send parts of it to a callback, as GByteArrays (must be cleaned
 *  by caller). */
GError* sqlx_repository_dump_base_chunked(struct sqlx_sqlite3_s *sq3,
		gint chunk_size, dump_base_chunked_cb callback, gpointer callback_arg);

// Perform a SQLite backup on the sqlite handles underlying two sqliterepo
// bases.
GError* sqlx_repository_backup_base(struct sqlx_sqlite3_s *src_sq3,
		struct sqlx_sqlite3_s *dst_sq3);

GError* sqlx_repository_restore_base(struct sqlx_sqlite3_s *sq3,
		guint8 *raw, gsize rawsize);
GError* sqlx_repository_restore_from_file(struct sqlx_sqlite3_s *sq3,
		const gchar *path);

GError* sqlx_repository_retore_from_master(struct sqlx_sqlite3_s *sq3);


/* ------------------------------------------------------------------------- */


GError* sqlx_transaction_prepare(struct sqlx_sqlite3_s *sq3,
		struct sqlx_repctx_s **result);

/**
 * Calls sqlx_transaction_prepare() and then calls the "BEGIN" SQL command.
 *
 * @see sqlx_transaction_prepare()
 * @param sq3
 * @return
 */
GError* sqlx_transaction_begin(struct sqlx_sqlite3_s *sq3,
		struct sqlx_repctx_s **result);

/**
 * @param repctx
 * @param err
 * @return
 */
GError* sqlx_transaction_end(struct sqlx_repctx_s *repctx, GError *err);

/**
 * @param ctx
 * @return
 */
struct sqlx_sqlite3_s* sqlx_transaction_get_base(struct sqlx_repctx_s *ctx);


/** Tells it will be necessary to immediately perform a RESYNC instead
 * of a regular REPLICATE operation. */
void sqlx_transaction_notify_huge_changes(struct sqlx_repctx_s *ctx);

/** @} */

#endif
