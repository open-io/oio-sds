/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__sqliterepo__election_h
# define OIO_SDS__sqliterepo__election_h 1

# include <glib.h>

struct election_counts_s
{
	guint total;
	guint none;
	guint pending;
	guint failed;
	guint master;
	guint slave;
};

/* Hidden type */
struct sqlx_repository_s;
struct election_manager_s;
struct sqlx_sync_s;
struct sqlx_name_s;

struct replication_config_s
{

	/** Tells the unique ID of the local service. */
	const gchar * (*get_local_url)(gpointer ctx);

	/** Locate the replication peers of the base identified by <n,t>. An error
	 * means the base cannot be replicated or managed. A base not managed
	 *  locally must return an error. A base locally managed but not replicated
	 *  must return NULL and fill result with a NULL pointer or an empty array.
	 *
	 * @param ctx the pointer registered in the configuration
	 * @param n the logical name of the base (not the physical path)
	 * @param result a placeholder for the array of peers.
	 * @return NULL if 'result'
	 */
	GError* (*get_peers) (gpointer ctx, struct sqlx_name_s *n,
			gboolean nocache, gchar ***result);

	/** Encapsulate the query for the DB's version */
	GError* (*get_version) (gpointer ctx, struct sqlx_name_s *n,
			GTree **result);

	gpointer ctx; /**< An arbitrary pointer reused in every hook. */

	enum election_mode_e {
		ELECTION_MODE_NONE = 0, /**< No replication */
		ELECTION_MODE_QUORUM,   /**< A master is found when a qualified majority
								 * of member is present */
		ELECTION_MODE_GROUP     /**< A master is found when the whole group
								 * agree */
	} mode; /**< Is replication activated */
};

struct election_manager_vtable_s
{
	/** Destroys an election_manager created by election_manager_create() */
	void (*clean) (struct election_manager_s *);

	/** Returns a pointer to the internal config of the manager */
	const struct replication_config_s* (*get_config) (const struct election_manager_s *);

	/** Run all the elections failed/pending for too long, then kick them off */
	guint (*retry_elections) (struct election_manager_s*,
			guint, GTimeVal*);

	/** Exit all elections older than 'max' */
	void (*exit_all) (struct election_manager_s *,
			GTimeVal *max, gboolean persist);

	/** Run all the elections and count them, grouped by status */
	struct election_counts_s (*count) (struct election_manager_s *);

	/** Prepare the internal memory for the election context, but without
	 * starting the election. Usefull to prepare. */
	GError* (*election_init) (struct election_manager_s *manager,
			struct sqlx_name_s *n);

	/** Triggers the global election mechanism then returns without
	 * waiting for a final status. */
	GError* (*election_start) (struct election_manager_s *manager,
			struct sqlx_name_s *n);

	GError* (*election_exit) (struct election_manager_s *manager,
			struct sqlx_name_s *n);

	GError* (*election_has_peers) (struct election_manager_s *manager,
			struct sqlx_name_s *n, gboolean *ppeers);

	GError* (*election_get_peers) (struct election_manager_s *manager,
			struct sqlx_name_s *n, gchar ***peers);

	/** Triggers the global election mechanism then wait for a final status
	 * have been locally hit.  */
	enum election_status_e (*election_get_status) (struct election_manager_s *manager,
			struct sqlx_name_s *n,
			gchar **master_url);

	GError* (*election_trigger_RESYNC) (struct election_manager_s *m,
			struct sqlx_name_s *n);

	/** Give the status for an election */
	void (*election_whatabout) (struct election_manager_s *m,
			struct sqlx_name_s *n,
			gchar *d, gsize ds);
};

struct abstract_election_manager_s {
	struct election_manager_vtable_s *vtable;
};

/* ------------------------------------------------------------------------- */

#define election_manager_clean(m) \
	((struct abstract_election_manager_s*)m)->vtable->clean(m)

#define election_manager_get_config0(m) \
	(((struct abstract_election_manager_s*)m)->vtable->get_config(m))

#define election_manager_get_config(m) \
	((m==NULL) ? NULL : election_manager_get_config0(m))

#define election_manager_retry_elections(m,max,end) \
	((struct abstract_election_manager_s*)m)->vtable->retry_elections(m,max,end)

#define election_manager_exit_all(m,max,persist) \
	((struct abstract_election_manager_s*)m)->vtable->exit_all(m,max,persist)

#define election_manager_count(m) \
	((struct abstract_election_manager_s*)m)->vtable->count(m);

#define election_init(m,n) \
	((struct abstract_election_manager_s*)m)->vtable->election_init(m,n)

#define election_start(m,n) \
	((struct abstract_election_manager_s*)m)->vtable->election_start(m,n)

#define election_has_peers(m,n,ppresent) \
	((struct abstract_election_manager_s*)m)->vtable->election_has_peers(m,n,ppresent)

#define election_get_peers(m,n,peers) \
	((struct abstract_election_manager_s*)m)->vtable->election_get_peers(m,n,peers)

#define election_exit(m,n) \
	((struct abstract_election_manager_s*)m)->vtable->election_exit(m,n)

#define election_get_status(m,n,pmaster) \
	((struct abstract_election_manager_s*)m)->vtable->election_get_status(m,n,pmaster)

#define election_manager_trigger_RESYNC(m,n) \
	((struct abstract_election_manager_s*)m)->vtable->election_trigger_RESYNC(m,n)

#define election_manager_whatabout(m,n,d,ds) \
	((struct abstract_election_manager_s*)m)->vtable->election_whatabout(m,n,d,ds)

/* Implementation-specific operations -------------------------------------- */

/** Creates the election_manager structure.  */
GError* election_manager_create (struct replication_config_s *config,
		struct election_manager_s **result);

/** Associate a gridd_client_pool to the given election_manager. The manager
 * is not responsible for that pool, it won't destroy it. */
void election_manager_set_clients (struct election_manager_s *m,
		struct gridd_client_pool_s *cp);

void election_manager_set_sync (struct election_manager_s *m,
		struct sqlx_sync_s *ss);

/* Implementation-specific operations -------------------------------------- */

/** Wraps the call to the hook in the config structure */
const gchar *sqlx_config_get_local_url(const struct replication_config_s *cfg);

/** Wraps the call to the hook in the config structure */
GError* sqlx_config_get_peers(const struct replication_config_s *cfg,
		struct sqlx_name_s *n, gchar ***result);

/** Wraps the call to the hook in the config structure */
GError* sqlx_config_get_peers2(const struct replication_config_s *cfg,
		struct sqlx_name_s *n, gboolean nocache, gchar ***result);

/** Wraps the call to the hook in the config structure */
GError* sqlx_config_has_peers(const struct replication_config_s *cfg,
		struct sqlx_name_s *n, gboolean *result);

GError* sqlx_config_has_peers2(const struct replication_config_s *cfg,
		struct sqlx_name_s *n, gboolean nocache, gboolean *result);

#endif /*OIO_SDS__sqliterepo__election_h*/
