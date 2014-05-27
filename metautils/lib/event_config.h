/*!
 * @file
 */

#ifndef GRID__EVTCONFIG_H
# define GRID__EVTCONFIG_H 1
# include <glib.h>

/**
 * @defgroup metautils_evtconfig Configuration for container notification events
 * @ingroup metautils_utils
 * @{
 */

/* hidden structures */
struct event_config_s;

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

/*! @} */

#endif /* GRID__EVTCONFIG_H */
