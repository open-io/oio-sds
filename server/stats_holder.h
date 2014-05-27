/**
 * @file stats_holder.h
 */

#ifndef GRID__STATS_HOLDER__H
# define GRID__STATS_HOLDER__H 1

/**
 * @defgroup server_stats Statistics support
 * @ingroup server
 * @brief Storage for named counters and gauges.
 * @details
 * All the functions are are synchronized on the holder itself.
 * @{
 */

# include <glib/gtypes.h>

/* Our hidden types */
struct grid_stats_holder_s;

struct grid_single_rrd_s;

/**
 * @return
 */
struct grid_stats_holder_s * grid_stats_holder_init(void);

/**
 * @param gsh
 */
void grid_stats_holder_clean(struct grid_stats_holder_s *gsh);

/**
 * Thread-safe
 *
 * @param gsh
 * @param ...
 */
void grid_stats_holder_set(struct grid_stats_holder_s *gsh, ...);

/**
 * Not thread-safe
 *
 * @param gsh
 * @param ...
 */
void grid_stats_holder_increment(struct grid_stats_holder_s *gsh, ...);

/**
 * Internal lock acquired
 *
 * @param gsh
 * @param ...
 */
void grid_stats_holder_get(struct grid_stats_holder_s *gsh, ...);

/**
 * Not thread-safe
 *
 * @param gsh
 */
void grid_stats_holder_zero(struct grid_stats_holder_s *gsh);

/**
 * Internal Lock acquired on base
 *
 * @param base
 * @param inc
 */
void grid_stats_holder_increment_merge(struct grid_stats_holder_s *base,
		struct grid_stats_holder_s *inc);

/**
 * Internal lock acquired on gsh
 *
 * @param gsh
 * @param pattern
 * @param output
 */
void grid_stats_holder_foreach(struct grid_stats_holder_s *gsh,
		const gchar *pattern,
		gboolean (*output)(const gchar *name, guint64 value));

/* ------------------------------------------------------------------------- */

/*!
 * @param period
 * @return
 */
struct grid_single_rrd_s* grid_single_rrd_create(time_t period);

/*!
 * @param gsr
 */
void grid_single_rrd_destroy(struct grid_single_rrd_s *gsr);

/*!
 * @param gsr
 * @param v
 */
void grid_single_rrd_push(struct grid_single_rrd_s *gsr, guint64 v);

/*!
 * @param gsr
 * @return
 */
guint64 grid_single_rrd_get(struct grid_single_rrd_s *gsr);

/*!
 * @param gsr
 * @param period
 * @return
 */
guint64 grid_single_rrd_get_delta(struct grid_single_rrd_s *gsr,
		time_t period);

/*!
 * Lock internally acquired on 'gsh'
 *
 * @param gsh
 * @param ... a NULL terminated sequence of (grid_single_rrd_s*, gchar*)
 */
void grid_single_rrd_feed(struct grid_stats_holder_s *gsh, ...);

/** @} */

#endif
