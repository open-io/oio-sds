/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__meta2v2__meta2_utils_lb_h
# define OIO_SDS__meta2v2__meta2_utils_lb_h 1

#include <core/oiolb.h>
#include <metautils/lib/metautils.h>
#include <glib.h>

#define RANDOM_UID(uid,uid_size) \
	struct { guint64 now; guint32 r; guint16 pid; guint16 th; } uid; \
	uid.now = oio_ext_real_time (); \
	uid.r = oio_ext_rand_int(); \
	uid.pid = getpid(); \
	uid.th = oio_log_current_thread_id(); \
	gsize uid_size = sizeof(uid);

GError* oio_generate_focused_beans(
		struct oio_url_s *url, gint64 pos, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct oio_lb_s *lb,
		oio_location_t pin, int mode,
		GSList **out);

/* @deprecated only used in a deprecated function of meta2 */
GError* oio_generate_beans(
		struct oio_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct oio_lb_s *lb,
		GSList **out);

/**
 * Get as many spare chunks as required to upload one metachunk with the
 * specified storage policy, starting at the `pin` location if the `mode`
 * allows it.
 */
GError* get_spare_chunks_focused(
		struct oio_url_s *url, const gchar *pos,
		struct oio_lb_s *lb,
		struct storage_policy_s *policy,
		oio_location_t pin, int mode,
		GSList **result);

/**
 * Get spare chunks according to a storage policy and lists of already
 * known chunks. Will return enough spare chunks to complete a metachunk,
 * or just one if the metachunk seems already complete.
 *
 * @param url URL of the object requiring spare chunks (with version)
 * @param position Position of the chunk which should be replaced.
 *   When using EC, you can ask for only one spare chunk at a time.
 *   When using replication, you can require several chunks for the
 *   same position.
 * @param lb Pointer to a rawx load balancing pool
 * @param stgpol Pointer to the wanted storage policy
 * @param ns_name Name of the namespace
 * @param notin The list of chunks that are already known and that are taken
 *   into account when computing distance
 * @param broken The list of chunks that are known to be broken and whose
 *   location should be avoided (do not count when computing distance)
 * @param result Pointer to a list where spare chunks will be inserted
 * @return A GError in case of error
 */
GError* get_conditioned_spare_chunks(
		struct oio_url_s *url, const gchar *position,
		struct oio_lb_s *lb,
		struct storage_policy_s *stgpol, const gchar *ns_name,
		GSList *notin, GSList *broken,
		GSList **result);

#endif /*OIO_SDS__meta2v2__meta2_utils_lb_h*/
