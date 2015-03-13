/*
OpenIO SDS metautils
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

#ifndef OIO_SDS__metautils__lib__event_config_h
# define OIO_SDS__metautils__lib__event_config_h 1

# include <glib.h>
# include <metautils/lib/metautils.h>

/**
 * @defgroup metautils_evtconfig Configuration for container notification events
 * @ingroup metautils_utils
 * @{
 */

/* hidden structures */
struct event_config_s;
struct event_config_repo_s;

/*!
 * @return
 */
struct event_config_s* event_config_create(void);

/*!
 * @param evt_config
 */
void event_config_destroy(struct event_config_s *evt_config);

GError* event_config_reconfigure(struct event_config_s *ec, const gchar *cfg);

/**
 * @param evt_config
 * @return
 */
gboolean event_is_enabled(struct event_config_s *evt_config);

/**
 * Are metautils events enabled?
 */
gboolean event_is_notifier_enabled(struct event_config_s *evt_config);

/**
 * Get the name of the metautils notifier topic defined in configuration.
 * If no topic is defined, return default_topic.
 */
const gchar *event_get_notifier_topic_name(struct event_config_s *evt_config,
		const gchar *default_topic);

/**
 * @param evt_config
 * @return
 */
gboolean event_is_aggregate(struct event_config_s *evt_config);

/**
 *
 *
 */
const gchar* event_get_dir(struct event_config_s *evt_config);

/**
 *
 *
 */
GMutex* event_get_lock(struct event_config_s *evt_config);

/**
 *
 *
 */
gint64 event_get_and_inc_seq(struct event_config_s *evt_config);

/*!
 * @param evt_config
 * @return
 */
gchar* event_config_dump(struct event_config_s *evt_config);

struct event_config_repo_s *event_config_repo_create(const gchar *ns_name,
	struct grid_lbpool_s *lbpool);
void event_config_repo_clear(struct event_config_repo_s **repo);

struct event_config_s* event_config_repo_get(
	struct event_config_repo_s *conf, const char *ns_name,
	gboolean vns_fallback);

metautils_notifier_t *event_config_repo_get_notifier(
	struct event_config_repo_s *repo);

/*! @} */

#endif /*OIO_SDS__metautils__lib__event_config_h*/