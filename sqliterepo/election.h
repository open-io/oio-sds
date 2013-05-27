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
 * @file election.h
 */

#ifndef SQLX__ELECTION_H
# define SQLX__ELECTION_H 1

/**
 * @defgroup sqliterepo_election Elections
 * @ingroup sqliterepo
 * @brief
 * @details
 *
 * @{
 */

# include <glib.h>
# include "./sqliterepo.h"

/**
 *
 */
enum election_status_e
{
	ELECTION_LOST = 1,   /**<  */
	ELECTION_LEADER = 2, /**<  */
	ELECTION_FAILED = 4  /**<  */
};

/* Hidden type */
struct election_manager_s;

/** Creates the election_manager structure.
 *
 * @param config the Namespace the election manager is working for
 * @param repo
 * @param result
 * @return
 */
GError* election_manager_create(struct replication_config_s *config,
		struct sqlx_repository_s *repo, struct election_manager_s **result);

/**
 * @param manager
 * @return
 */
const struct replication_config_s * election_manager_get_config(
		const struct election_manager_s *manager);

/**
 * @param manager
 * @param name
 * @param type
 */
void election_init(struct election_manager_s *manager,
		const gchar *name, const gchar *type);

/** Triggers the global election mechanism then returns without
 * waiting for a final status.
 *
 * @param manager
 * @param name
 * @param type
 */
void election_start(struct election_manager_s *manager,
		const gchar *name, const gchar *type);

/**
 * @param manager
 * @param name
 * @param type
 */
gboolean election_has_peers(struct election_manager_s *manager,
		const gchar *name, const gchar *type);

/**
 * @param manager
 * @param name
 * @param type
 */
void election_exit(struct election_manager_s *manager,
		const gchar *name, const gchar *type);

/** Triggers the global election mechanism then wait for a final status
 * have been locally hit.
 *
 * @param manager
 * @param name
 * @param type
 * @param master_url
 * @return
 */
enum election_status_e election_get_status(
		struct election_manager_s *manager, const gchar *name,
		const gchar *type, gchar **master_url);

/**
 * @param manager
 */
void election_manager_clean(struct election_manager_s *manager);

/**
 * @param m no-op if NULL
 * @param max
 * @param pivot
 * @param end
 * @return the number of elections really reactived
 */
guint election_manager_retry_elections(struct election_manager_s *m,
		guint max, GTimeVal *pivot, GTimeVal *end);

/**
 * @param m
 * @param max seconds to wait
 * @return
 */
GError * election_manager_clients_round(struct election_manager_s *m,
		time_t max);

/**
 * @param m not NULL
 * @param max >= 2
 */
void election_manager_clients_setmax(struct election_manager_s *m, guint max);

/**
 * @param m
 * @param name
 * @param type
 */
GError * election_manager_trigger_RESYNC(struct election_manager_s *m,
		const gchar *name, const gchar *type);

/**
 * @param manager
 * @param max
 */
void election_manager_exit_all(struct election_manager_s *manager,
		GTimeVal *max);

/**
 * @param m
 * @param name
 * @param type
 * @param d
 * @param ds
 */
void election_manager_whatabout(struct election_manager_s *m,
		const gchar *name, const gchar *type, gchar *d, gsize ds);

/** @} */

#endif /* SQLX__ELECTION_H */
