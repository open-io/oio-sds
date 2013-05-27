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

# define SQLX_RC_BASE_LOCKED              -6
# define SQLX_RC_TOOMANY                  -5
# define SQLX_RC_INVALID_BASE_ID          -4
# define SQLX_RC_BASE_CLOSED              -3
# define SQLX_RC_NOT_IMPLEMENTED          -2
# define SQLX_RC_DESIGN_ERROR             -1
# define SQLX_RC_NOERROR                   0
# define SQLX_RC_INVALID_SCHEMA            1

# include <unistd.h>
# include <glib.h>
# include <sqlite3.h>
# include "../metautils/lib/loggers.h"
# include "./sqlite_utils.h"

struct hashstr_s;

struct sqlx_repctx_s;

struct sqlx_sqlite3_s;

typedef struct sqlx_repository_s sqlx_repository_t;

typedef void (*sqlx_repo_close_hook)(sqlx_repository_t *repo,
		const gchar *n, const gchar *t, gpointer cb_data);

typedef GError* (*sqlx_repo_open_hook)(struct sqlx_sqlite3_s *sq3,
		gpointer cb_data);

/**
 */
struct replication_config_s
{
	enum election_mode_e {
		ELECTION_MODE_NONE = 0, /**< No replication */
		ELECTION_MODE_QUORUM,   /**< A master is found when a qualified majority
								 * of member is present */
		ELECTION_MODE_GROUP     /**< A master is found when the whole group
								 * agree */
	} mode; /**< Is replication activated */

	gpointer ctx; /**< An arbitrary pointer reused in every hook. */

	/**
	 * @param ctx
	 * @return
	 */
	const gchar * (*get_manager_url)(gpointer ctx);

	/**
	 * @param ctx
	 * @return
	 */
	const gchar * (*get_ns_name)(gpointer ctx);

	/**
	 * @param ctx
	 * @return
	 */
	const gchar * (*get_local_url)(gpointer ctx);

	/** 
	 * @param ctx
	 * @param n
	 * @param t
	 * @return
	 */
	gchar ** (*get_peers) (gpointer ctx, const gchar *n, const gchar *t);

	const gchar *subpath; /**< The subdirectory in zookeeper */
	gint hash_depth;
	gint hash_width;
};

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
	gint bd;
	sqlite3 *db;
	gchar *logical_name;
	gchar *logical_type;
	gchar *path;
	GTree *versions;
	gboolean deleted;
};

enum sqlx_repo_flag_e
{
	SQLX_REPO_NOCACHE = 0x01,
	SQLX_REPO_VACUUM  = 0x02,
	SQLX_REPO_DELETEON = 0x04,
	SQLX_REPO_NOLOCK = 0x08,
	SQLX_REPO_AUTOCREATE = 0x10
};

/* Init and configure ------------------------------------------------------ */

struct sqlx_repo_config_s
{
	enum sqlx_repo_flag_e flags; /**< several options. */
	struct {
		const gchar *ns; /**< The name of the physical NS of the repository */
		const gchar *type; /**< The service type used for locking */
		const gchar *srv; /**< a unique ID for the service, i.e. its service
						   * IP:PORT */
	} lock;
};

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
GError * sqlx_repository_init(const gchar *vol, struct sqlx_repo_config_s *cfg,
		sqlx_repository_t **result);

/**
 * @param repo
 * @param locator
 * @param locator_data
 */
void sqlx_repository_set_locator(struct sqlx_repository_s *repo,
		sqlx_file_locator_f locator, gpointer locator_data);

/** Cleans all the structures associated with the given repository.
 *
 * @param repo the repository to be destroyed
 */
void sqlx_repository_clean(sqlx_repository_t *repo);


/**
 * @param repo
 * @param width
 * @param depth
 */
void sqlx_repository_configure_hash(sqlx_repository_t *repo,
		guint width, guint depth);


/** Calling this function on a repository that already managed a base has no
 * effect.
 *
 * @param repo
 * @param max
 */
void sqlx_repository_configure_maxbases(sqlx_repository_t *repo,
		guint max);


/**
 * @param repo
 * @param config
 * @return
 */
GError* sqlx_repository_configure_replication(sqlx_repository_t *repo,
		struct replication_config_s *config);


/**
 * @param repo
 * @param max
 * @return
 */
GError* sqlx_repository_clients_round(sqlx_repository_t *repo, time_t max);


/* Schema operations ------------------------------------------------------- */

/**
 * @param repo
 * @param type
 * @param schema
 * @return
 */
GError* sqlx_repository_configure_type(sqlx_repository_t *repo,
		const gchar *type, const gchar *version, const gchar *schema);


/**
 * @param repo
 * @param cb
 * @param cb_data
 */
void sqlx_repository_configure_close_callback(sqlx_repository_t *repo,
		sqlx_repo_close_hook cb, gpointer cb_data);

/**
 * @param repo not NULL
 * @param cb not NULL
 * @param cb_data whatever
 */
void sqlx_repository_configure_open_callback(sqlx_repository_t *repo,
		sqlx_repo_open_hook cb, gpointer cb_data);

/* Bases operations -------------------------------------------------------- */

/**
 * @param sq3
 * @param result
 * @return
 */
GError * sqlx_repository_get_version(struct sqlx_sqlite3_s *sq3,
		GTree **result);


/** Opens the base (locally) then calls sqlx_repository_get_version() before
 * closing it.
 *
 * @param repo
 * @param type
 * @param name
 * @param result
 */
GError * sqlx_repository_get_version2(sqlx_repository_t *repo,
		const gchar *type, const gchar *name, GTree **result);


/* ------------------------------------------------------------------------- */

/**
 * @param sq3
 * @return
 */
GError* sqlx_repository_unlock_and_close(struct sqlx_sqlite3_s *sq3);

/**
 * @param sq3
 * @see sqlx_repository_unlock_and_close()
 */
void sqlx_repository_unlock_and_close_noerror(struct sqlx_sqlite3_s *sq3);

enum sqlx_open_type_e
{
	SQLX_OPEN_LOCAL = 0x00,
	SQLX_OPEN_MASTERONLY = 0x01,
	SQLX_OPEN_MASTERSLAVE = 0x02,
	SQLX_OPEN_SLAVEONLY = 0x03,

	SQLX_OPEN_CREATE = 0x10
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

/* ------------------------------------------------------------------------- */

/**
 *
 * @param repo
 * @param type
 * @param name
 * @return
 */
GError* sqlx_repository_prepare_election(sqlx_repository_t *repo,
		const gchar *type, const gchar *name);

/**
 *
 * @param repo
 * @param type
 * @param name
 * @return
 */
GError* sqlx_repository_exit_election(sqlx_repository_t *repo,
		const gchar *type, const gchar *name);

/** Triggers the global election mechanism on a base given its name
 *
 * @param repo
 * @param type
 * @param name
 * @return 
 */
GError* sqlx_repository_use_base(sqlx_repository_t *repo,
		const gchar *type, const gchar *name);


/** Triggers the global election mechanism on a base given its name and
 * returns when a final status (or a timeout) has been reached.
 *
 * @param repo
 * @param type
 * @param name
 * @return NULL if master, an error with code 303 if slave, an error with 
 *         another code if the election failed.
 */
GError* sqlx_repository_status_base(sqlx_repository_t *repo,
		const gchar *type, const gchar *name);


/** Close idle bases
 * @param r
 * @param max max number of bases managed
 * @param pivot only consider bases before pivot
 * @param end stop working until end i reached
 * @return
 */
guint sqlx_repository_expire_bases(sqlx_repository_t *r, guint max,
		GTimeVal *pivot, GTimeVal *end);


/** Voluntarily leave election groups.
 *
 * The sqlx_repository_t won't be useable after this.
 *
 * @param r
 * @param max
 */
void sqlx_repository_exit_elections(sqlx_repository_t *r, GTimeVal *max);


/** Reactivates stalled elections
 * @param r
 * @param max
 * @param pivot
 * @param end
 * @return
 */
guint sqlx_repository_retry_elections(sqlx_repository_t *r, guint max,
		GTimeVal *pivot, GTimeVal *end);

/** Get the internal handle associated to an opened database.
 * @param r
 * @param bd
 * @param result
 * @return NULL
 */
GError* sqlx_repository_get_handle(sqlx_repository_t *r, gint bd,
		struct sqlx_sqlite3_s **result);

/**
 * @param sq3
 * @param dump
 * @return
 */
GError* sqlx_repository_dump_base(struct sqlx_sqlite3_s *sq3,
		GByteArray **dump);

GError*
sqlx_repository_backup_base(struct sqlx_sqlite3_s *src_sq3,struct sqlx_sqlite3_s *dst_sq3);

/**
 * @param sq3
 * @param raw
 * @param rawsize
 * @return
 */
GError* sqlx_repository_restore_base(struct sqlx_sqlite3_s *sq3,
		guint8 *raw, gsize rawsize);


/**
 * @param sq3
 * @return
 */
GError* sqlx_repository_retore_from_master(struct sqlx_sqlite3_s *sq3);


/**
 *
 * @param r
 * @param type
 * @param name
 * @param dst
 * @param dstsize
 */
void sqlx_repository_whatabout(sqlx_repository_t *r, const gchar *type,
		const gchar *name, gchar *dst, gsize dstsize);

/**
 * @param r may be NULL
 * @return
 */
gboolean sqlx_repository_replication_configured(const struct sqlx_repository_s *r);

/* ------------------------------------------------------------------------- */

/**
 * Prepare all the structures involved in a replicated transaction and
 * attaches the callbacks.
 *
 * @param sq3
 * @return
 */
struct sqlx_repctx_s* sqlx_transaction_prepare(struct sqlx_sqlite3_s *sq3);

/**
 * Calls sqlx_transaction_prepare() and then calls the "BEGIN" SQL command.
 *
 * @see sqlx_transaction_prepare()
 * @param sq3
 * @return
 */
struct sqlx_repctx_s* sqlx_transaction_begin(struct sqlx_sqlite3_s *sq3);

/**
 * @param ctx
 */
void sqlx_transaction_detach(struct sqlx_repctx_s *ctx);

/**
 * @param repctx
 */
void sqlx_transaction_changes(struct sqlx_repctx_s *repctx);

/**
 * @param repctx
 * @param err
 * @return
 */
GError* sqlx_transaction_end(struct sqlx_repctx_s *repctx, GError *err);


/**
 * @param repctx
 */
void sqlx_transaction_destroy(struct sqlx_repctx_s *repctx);


/**
 * @param ctx
 * @return
 */
struct sqlx_sqlite3_s* sqlx_transaction_get_base(struct sqlx_repctx_s *ctx);


/**
 * The result of this function is to 
 */
void sqlx_transaction_notify_huge_changes(struct sqlx_repctx_s *ctx);

/** @} */

#endif
