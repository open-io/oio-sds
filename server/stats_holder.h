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

/*! Allocates a round-robin set of metrics, working on <period> slots. */
struct grid_single_rrd_s* grid_single_rrd_create(time_t now, time_t period);

/*! Cleans all the resources used by the rrd. */
void grid_single_rrd_destroy(struct grid_single_rrd_s *gsr);

/*! Save a default value to be used for the slots where there is no
 * activity. */
void grid_single_rrd_set_default(struct grid_single_rrd_s *gsr,
		guint64 def);

/*! forces an absolute value for the current position */
void grid_single_rrd_push(struct grid_single_rrd_s *gsr,
		time_t at, guint64 v);

/*! forces an absolute value for the current position */
void grid_single_rrd_pushifmax(struct grid_single_rrd_s *gsr,
		time_t at, guint64 v);

/*! Get the value in the current slot of the rrd. */
guint64 grid_single_rrd_get(struct grid_single_rrd_s *gsr, time_t at);

/*! Compute the difference between the current value and the value that
 * is <period> seconds old. */
guint64 grid_single_rrd_get_delta(struct grid_single_rrd_s *gsr,
		time_t at, time_t period);

/*! Computes the maximal value among the set not older than <period> seconds. */
guint64 grid_single_rrd_get_max(struct grid_single_rrd_s *gsr,
		time_t at, time_t period);

/*! Cumulates all the maximum values, for all the periods between
 * 1 and the given <period>. Single run! */
void grid_single_rrd_get_allmax(struct grid_single_rrd_s *gsr,
		time_t at, time_t period, guint64 *out);

/*! Lock internally acquired on 'gsh'
 * @param gsh
 * @param ... a NULL terminated sequence of (grid_single_rrd_s*, gchar*)
 */
void grid_single_rrd_feed(struct grid_stats_holder_s *gsh,
		time_t now, ...);

/** @} */

#endif
