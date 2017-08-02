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

/**
 * Signature of functions converting (struct service_info_s *)
 * to chunk information.
 */
typedef gpointer (*srvinfo_to_chunk_f)(struct service_info_s *si);

/**
 * Get as many spare chunks as required to upload one metachunk with the
 * specified storage policy.
 *
 * @param lb Pointer to a load balancer
 * @param stgpol_name Name of the wanted storage policy
 * @param result Pointer to a list where spare chunks will be inserted
 * @return A GError in case of error
 */
GError* get_spare_chunks(struct oio_lb_s *lb,
		const char *stgpol_name, GSList **result);

/**
 * Get spare chunks according to a storage policy and lists of already
 * known chunks. Will return enough spare chunks to complete a metachunk,
 * or just one if the metachunk seems already complete.
 *
 * @param lbp Pointer to a rawx load balancing pool
 * @param stgpol Pointer to the wanted storage policy
 * @param ns_name Name of the namespace
 * @param notin The list of chunks that are already known and that are taken
 *   into account when computing distance
 * @param broken The list of chunks that are known to be broken and whose
 *   location should be avoided (do not count when computing distance)
 * @param result Pointer to a list where spare chunks will be inserted
 * @return A GError in case of error
 */
GError* get_conditioned_spare_chunks(struct oio_lb_s *lbp,
		const char *stgpol, const gchar *ns_name,
		GSList *notin, GSList *broken,
		GSList **result);

#endif /*OIO_SDS__meta2v2__meta2_utils_lb_h*/
