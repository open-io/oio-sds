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
struct election_member_s;
struct sqlx_sync_s;
struct sqlx_peering_s;
struct sqlx_name_s;

enum election_mode_e
{
	/* No replication */
	ELECTION_MODE_NONE = 0,
	/* A master is found when a qualified majority of member is present */
	ELECTION_MODE_QUORUM,
	/* A master is found when the whole group agree */
	ELECTION_MODE_GROUP
};

enum election_step_e
{
	STEP_NONE = 0,

	STEP_PEERING,

	STEP_CREATING,
	STEP_WATCHING,
	STEP_LISTING,
	STEP_ASKING,
	STEP_CHECKING_MASTER,
	STEP_CHECKING_SLAVES,
	STEP_SYNCING,

	STEP_DELAYED_CHECKING_MASTER,
	STEP_REFRESH_CHECKING_MASTER,

	STEP_DELAYED_CHECKING_SLAVES,
	STEP_REFRESH_CHECKING_SLAVES,

	STEP_LEAVING,
	STEP_LEAVING_FAILING,
	STEP_FAILED,

	/* final */
	STEP_SLAVE,
	STEP_MASTER,
#define STEP_MAX (STEP_MASTER+1)
};

struct replication_config_s
{
	/** Tells the unique ID of the local service. */
	const char * (*get_local_url) (gpointer ctx);

	/** Locate the replication peers of the base identified by <n,t>. An error
	 * means the base cannot be replicated or managed. A base not managed
	 *  locally must return an error. A base locally managed but not replicated
	 *  must return NULL and fill result with an empty array.
	 *
	 * @param ctx the pointer registered in the configuration
	 * @param n the logical name of the base (not the physical path)
	 * @param nocache
	 * @param result a placeholder for the array of peers.
	 * @return NULL if 'result' is set, and not-NULL if 'result' is not set
	 */
	GError* (*get_peers) (gpointer ctx, const struct sqlx_name_s *n,
			gboolean nocache, gchar ***result);

	/** Encapsulate the query for the DB's version */
	GError* (*get_version) (gpointer ctx, const struct sqlx_name_s *n,
			GTree **result);

	gpointer ctx; /**< An arbitrary pointer reused in every hook. */

	enum election_mode_e mode; /**< Is replication activated */
};

struct election_manager_vtable_s
{
	/** Destroys an election_manager created by election_manager_create() */
	void (*clean) (struct election_manager_s *);


	/* is replication configured, and how */
	enum election_mode_e (*get_mode) (const struct election_manager_s *);

	/* return the ID ofthe local service */
	const char * (*get_local) (const struct election_manager_s *);

	/* who are the peers for the given base */
	GError* (*election_get_peers) (struct election_manager_s *manager,
			const struct sqlx_name_s *n, guint32 flags, gchar ***peers);

	/** Prepare the internal memory for the election context, but without
	 * starting the election. Usefull to prepare. */
	GError* (*election_init) (struct election_manager_s *manager,
			const struct sqlx_name_s *n,
			const gchar *peers,
			enum election_step_e *out_status,
			gboolean *replicated);

	/** Triggers the global election mechanism then returns without
	 * waiting for a final status. */
	GError* (*election_start) (struct election_manager_s *manager,
			const struct sqlx_name_s *n);

	GError* (*election_exit) (struct election_manager_s *manager,
			const struct sqlx_name_s *n);

	/** Triggers the global election mechanism then wait for a final status
	 * have been locally hit.  */
	enum election_status_e (*election_get_status) (
			struct election_manager_s *manager,
			const struct sqlx_name_s *n,
			gchar **master_url,
			gint64 deadline);

	GError* (*election_trigger_RESYNC) (struct election_manager_s *m,
			const struct sqlx_name_s *n, const gint check_type);
};

struct abstract_election_manager_s
{
	struct election_manager_vtable_s *vtable;
};

/* ------------------------------------------------------------------------- */

#define election_manager_clean(m) \
	((struct abstract_election_manager_s*)m)->vtable->clean(m)

enum election_mode_e election_manager_get_mode (const struct election_manager_s *);

const char * election_manager_get_local (const struct election_manager_s *m);

GError* election_get_peers (struct election_manager_s *manager,
		const struct sqlx_name_s *n, guint32 flags, gchar ***peers);

#define election_init(m,n,peers,out,replicated) \
	((struct abstract_election_manager_s*)m)->vtable->election_init(m,n,peers,out,replicated)

#define election_start(m,n) \
	((struct abstract_election_manager_s*)m)->vtable->election_start(m,n)

#define election_exit(m,n) \
	((struct abstract_election_manager_s*)m)->vtable->election_exit(m,n)

#define election_get_status(m,n,pmaster,deadline) \
	((struct abstract_election_manager_s*)m)->vtable->election_get_status(\
		m,n,pmaster,deadline)

#define election_manager_trigger_RESYNC(m,n,c) \
	((struct abstract_election_manager_s*)m)->vtable->election_trigger_RESYNC(m,n,c)

/* wraps election_get_peers() */
GError * election_has_peers (struct election_manager_s *m,
		const struct sqlx_name_s *n, gboolean nocache, gboolean *ppresent);

/* Implementation-specific operations -------------------------------------- */

/* Creates the election_manager structure.  */
GError* election_manager_create (struct replication_config_s *config,
		struct election_manager_s **result);

void election_manager_dump_delays(void);

struct election_counts_s election_manager_count (struct election_manager_s *m);

/* Make some elections leave their MASTER state if they are inactive since
 * longer than `inactivity`, but not more than `max` elections. */
guint election_manager_balance_masters(struct election_manager_s *M,
		guint max, gint64 inactivity);

/* When is the next action to fire (timer or expiration).
 * Return 0 if there is none. */
gint64 election_manager_next_timer(struct election_manager_s *m);

void election_manager_play_timers(struct election_manager_s *m, const gint64 now);

void election_manager_play_expirations(struct election_manager_s *m, const gint64 now);

/* Similar to the MANAGER_CHECK macro, but not stripped in Release mode,
 * and returns a boolean instead of asserting. */
gboolean election_manager_is_operational(struct election_manager_s *manager);

void election_manager_exit_all (struct election_manager_s *m, gint64 oldest);

void election_manager_whatabout (struct election_manager_s *m,
		const struct sqlx_name_s *n, GString *out);

void election_manager_add_sync(struct election_manager_s *manager,
		struct sqlx_sync_s *sync);

void election_manager_set_peering (struct election_manager_s *m,
		struct sqlx_peering_s *peering);

gboolean election_manager_configured(const struct election_manager_s *m);

#endif /*OIO_SDS__sqliterepo__election_h*/
