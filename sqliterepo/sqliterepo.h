/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__sqliterepo__sqliterepo_h
# define OIO_SDS__sqliterepo__sqliterepo_h 1

# include <unistd.h>
# include <sqlite3.h>
# include <metautils/lib/metautils.h>
# include <sqliterepo/sqlite_utils.h>
# include <sqliterepo/sqlx_remote.h>

enum sqlx_open_type_e;

struct hashstr_s;
struct replication_config_s;
struct election_manager_s;

struct sqlx_cache_s;
struct sqlx_repctx_s;
struct sqlx_sqlite3_s;
struct sqlx_name_s;

typedef struct sqlx_repository_s sqlx_repository_t;

typedef GError* (*sqlx_repo_open_hook)(struct sqlx_sqlite3_s *sq3,
		gpointer cb_data, enum sqlx_open_type_e open_mode);

typedef void (*sqlx_repo_close_hook)(struct sqlx_sqlite3_s *sq3,
		gpointer cb_data);

typedef void (*sqlx_repo_change_hook)(struct sqlx_sqlite3_s *sq3,
		gpointer cb_data);

typedef void (*sqlx_repo_db_properties_change_hook)(struct sqlx_sqlite3_s *sq3,
		gpointer cb_data, struct oio_url_s *url,
		struct db_properties_s *db_properties);

typedef void (*sqlx_file_locator_f) (gpointer locator_data,
		const struct sqlx_name_s *n, GString *file_name);

enum sqlx_open_type_e
{
	SQLX_OPEN_LOCAL       = 0x00,
	SQLX_OPEN_MASTERONLY  = 0x01,
	SQLX_OPEN_SLAVEONLY   = 0x02,
	SQLX_OPEN_MASTERSLAVE = 0x03,
#define SQLX_OPEN_REPLIMODE 0x0F

	SQLX_OPEN_CREATE      = 0x10,
	SQLX_OPEN_NOREFCHECK  = 0x20,
	SQLX_OPEN_URGENT      = 0x40,
#define SQLX_OPEN_FLAGS     0x0F0

	// Set an OR'ed combination of the following flags to require
	// a check on the container's status during the open phase.
	// No flag set means no check.
	SQLX_OPEN_ENABLED     = 0x100,
	SQLX_OPEN_FROZEN      = 0x200,
	SQLX_OPEN_DISABLED    = 0x400,
#define SQLX_OPEN_STATUS    0xF00
};

enum sqlx_close_flag_e
{
	/** Close the base immediately, don't keep it in the cache */
	SQLX_CLOSE_IMMEDIATELY  = 0x01,
	/** Close the base immediately,
	 *  and prevent other threads from reopening it. */
	SQLX_CLOSE_FOR_DELETION = 0x02,
};

enum sqlx_repo_flag_e
{
	SQLX_REPO_NOCACHE      = 0x01,
	SQLX_REPO_VACUUM       = 0x02,
	SQLX_REPO_DELETEON     = 0x04,
};

enum election_status_e
{
	ELECTION_LOST = 1,
	ELECTION_LEADER = 2,
	ELECTION_FAILED = 4
};

struct sqlx_sqlite3_s
{
	struct sqlx_repository_s *repo;
	struct election_manager_s *manager;
	GTree *admin; // <gchar*,GByteArray*>
	sqlite3 *db;

	gint bd; // ID in cache
	enum election_status_e election : 8; // set at open(), reset at close()

	guint8 admin_dirty : 1;
	guint8 deleted : 1;
	guint8 no_peers : 1; // Prevent get_peers()
	guint8 corrupted : 1; // Will rename the file when closing database.

	struct sqlx_name_inline_s name;
	gchar path_inline[128 + LIMIT_LENGTH_NSNAME + LIMIT_LENGTH_SRVTYPE];
};

struct sqlx_repo_config_s
{
	/** several options. */
	enum sqlx_repo_flag_e flags;
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

/* The cleanup is not performed during the sqlx_repository_init() because we
 * prefer ensuring we are the only process with an access granted. */
void sqlx_repository_initial_cleanup(sqlx_repository_t *repo);

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

/** Register a new DB type with its schema.  */
GError* sqlx_repository_configure_type(sqlx_repository_t *repo,
		const char *type, const char *schema);

void sqlx_repository_configure_open_callback(
		sqlx_repository_t *repo,
		sqlx_repo_open_hook cb, gpointer cb_data);

GError* sqlx_repository_call_open_callback(
		struct sqlx_sqlite3_s *sq3, enum sqlx_open_type_e open_mode);

void sqlx_repository_configure_close_callback(sqlx_repository_t *repo,
		sqlx_repo_close_hook cb, gpointer cb_data);

void sqlx_repository_call_close_callback(struct sqlx_sqlite3_s *sq3);

void sqlx_repository_configure_change_callback(sqlx_repository_t *repo,
		sqlx_repo_change_hook cb, gpointer cb_data);

void sqlx_repository_call_change_callback(struct sqlx_sqlite3_s *sq3);

void sqlx_repository_configure_db_properties_change_callback(
		sqlx_repository_t *repo,
		sqlx_repo_db_properties_change_hook cb, gpointer cb_data);

void sqlx_repository_call_db_properties_change_callback(
		struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct db_properties_s *db_properties);

/* Bases operations -------------------------------------------------------- */

GError* sqlx_repository_timed_open_and_lock(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, enum sqlx_open_type_e how,
		const gchar *peers,
		struct sqlx_sqlite3_s **sq3, gchar **lead,
		gint64 deadline);

GError* sqlx_repository_open_and_lock(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, enum sqlx_open_type_e how,
		struct sqlx_sqlite3_s **sq3, gchar **lead);

/** The complement of sqlx_repository_open_and_lock() */
GError* sqlx_repository_unlock_and_close(struct sqlx_sqlite3_s *sq3);

/**
 * @param flags OR'ed close flags (see sqlx_close_flag_e) */
GError* sqlx_repository_unlock_and_close2(struct sqlx_sqlite3_s *sq3,
		guint32 flags);

/** @see sqlx_repository_unlock_and_close() */
void sqlx_repository_unlock_and_close_noerror(struct sqlx_sqlite3_s *sq3);

/** @param flags flags OR'ed close flags (see sqlx_close_flag_e) */
void sqlx_repository_unlock_and_close_noerror2(struct sqlx_sqlite3_s *sq3,
		guint32 flags);

/** Get the replication peers from the higher level service */
GError* sqlx_repository_get_peers(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, gchar ***result);

/** Get the replication peers from the local database */
GError* sqlx_repository_get_peers2(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, gchar ***result);

GError * sqlx_repository_get_version(struct sqlx_sqlite3_s *sq3,
		GTree **result);

/** Opens the base (locally) then calls sqlx_repository_get_version() before
 * closing it.  */
GError * sqlx_repository_get_version2(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, GTree **result);

GError* sqlx_repository_has_base2(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, gchar** bddname);

#define sqlx_repository_has_base(r,n) sqlx_repository_has_base2(r,n,NULL)

GError* sqlx_repository_remove_from_cache(sqlx_repository_t *repo,
		const struct sqlx_name_s *name);

GError* sqlx_repository_exit_election(sqlx_repository_t *repo,
		const struct sqlx_name_s *n);

/** Triggers the global election mechanism on a base given its name */
GError* sqlx_repository_use_base(sqlx_repository_t *repo,
		const struct sqlx_name_s *n,
		const gchar *peers,
		gboolean notify_master,
		gboolean allow_autocreate,
		gboolean *replicated);

/** Triggers the global election mechanism on a base given its name and
 * returns when a final status (or a timeout) has been reached.
 * @return NULL if master, an error with code CODE_REDIRECT if slave, an error with
 *         another code if the election failed. */
GError* sqlx_repository_status_base(sqlx_repository_t *repo,
		const struct sqlx_name_s *n, const gchar *peers, gint64 deadline);

/** Collect into a buffer the binary dump of the base (i.e. the content
 *  of a valid sqlite3 file, with only the meaningful pages). */
GError* sqlx_repository_dump_base_gba(struct sqlx_sqlite3_s *sq3,
		gint check_type, GByteArray **dump);

/** Callback for sqlx_repository_dump_base_fd(). */
typedef GError*(*dump_base_fd_cb)(int fd, gpointer arg);

/** Open a dump of the base (with only the meaningful pages)
 *  and pass the file descriptor to a callback. */
GError* sqlx_repository_dump_base_fd(struct sqlx_sqlite3_s *sq3,
		dump_base_fd_cb callback, gpointer callback_arg);

/** Open the database file read-only,
 *  check the file size against sqliterepo_dump_max_size if required,
 *  check the database integrity if required,
 *  and pass the file descriptor to a callback.
 *  Falls back on sqlx_repository_dump_base_fd in case of error. */
GError* sqlx_repository_dump_base_fd_no_copy(struct sqlx_sqlite3_s *sq3,
		gboolean check_size, gint check_type,
		dump_base_fd_cb read_file_cb, gpointer cb_arg);

/** Callback for sqlx_repository_dump_base_chunked() */
typedef GError*(*dump_base_chunked_cb)(GByteArray *gba, gint64 remaining_bytes,
		gpointer arg);

/** Open a dump of the base (with only the meaningful pages),
 *  and send parts of it to a callback, as GByteArrays (must be cleaned
 *  by caller). */
GError* sqlx_repository_dump_base_chunked(struct sqlx_sqlite3_s *sq3,
		gint chunk_size, gint check_type,
		dump_base_chunked_cb callback, gpointer callback_arg);

GError* sqlx_repository_restore_base(struct sqlx_sqlite3_s *sq3,
		guint8 *raw, gsize rawsize);

GError* sqlx_repository_restore_from_file(struct sqlx_sqlite3_s *sq3,
		const gchar *path);

GError* sqlx_repository_restore_from_master(struct sqlx_sqlite3_s *sq3,
		const gint check_type);

/* ------------------------------------------------------------------------- */

GError* sqlx_transaction_prepare(struct sqlx_sqlite3_s *sq3,
		struct sqlx_repctx_s **result);

/** Calls sqlx_transaction_prepare() and then calls the "BEGIN" SQL command.
 * @see sqlx_transaction_prepare() */
GError* sqlx_transaction_begin(struct sqlx_sqlite3_s *sq3,
		struct sqlx_repctx_s **result);

GError* sqlx_transaction_end(struct sqlx_repctx_s *repctx, GError *err);

/** Tells it will be necessary to immediately perform a RESYNC instead
 * of a regular REPLICATE operation. */
void sqlx_transaction_notify_huge_changes(struct sqlx_repctx_s *ctx);

#endif /*OIO_SDS__sqliterepo__sqliterepo_h*/
