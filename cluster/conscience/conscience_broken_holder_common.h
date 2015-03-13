/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__cluster__conscience__conscience_broken_holder_common_h
# define OIO_SDS__cluster__conscience__conscience_broken_holder_common_h 1

# include <glib.h>

/**
 * @addtogroup gridcluster_backend
 * @{
 */

/**
 */
struct broken_fields_s
{
	const gchar *packed;
	const gchar *ns;
	gchar *ip;
	gint port;
	gchar *cid;
	gchar *content;
	gchar *cause;
};

/**
 * @param bh
 * @param bf
 */
void broken_holder_add_meta1(struct broken_holder_s * bh, struct broken_fields_s * bf);

/**
 * @param bh
 * @param bf
 */
void broken_holder_add_in_meta2(struct broken_holder_s * bh, struct broken_fields_s * bf);

/*removers*/

/**
 * @param bh
 * @param bf
 */
void broken_holder_remove_meta2( struct broken_holder_s *bh, struct broken_fields_s *bf );

/**
 * @param bh
 * @param bf
 */
void broken_holder_remove_meta1( struct broken_holder_s *bh, struct broken_fields_s *bf );

/**
 * @param bh
 * @param bf
 */
void broken_holder_remove_content( struct broken_holder_s *bh, struct broken_fields_s *bf );

/**
 * @param bh
 * @param bf
 */
void broken_holder_remove_container( struct broken_holder_s *bh, struct broken_fields_s *bf );

/*fixers*/

/**
 * @param bh
 * @param bf
 */
void broken_holder_fix_meta1(struct broken_holder_s * bh, struct broken_fields_s *bf);

/**
 * @param bh
 * @param bf
 */
void broken_holder_fix_meta2(struct broken_holder_s * bh, struct broken_fields_s *bf);

/**
 * @param bh
 * @param bf
 * @param brk_m2
 */
void broken_holder_fix_content(struct broken_holder_s *bh, struct broken_fields_s *bf, struct broken_meta2_s *brk_m2);

/**
 * @param bh
 * @param bf
 * @param brk_m2
 */
void broken_holder_fix_container(struct broken_holder_s *bh, struct broken_fields_s *bf, struct broken_meta2_s *brk_m2);

/**
 * @param bh
 * @param bf
 */
void broken_holder_fix_in_meta2(struct broken_holder_s * bh, struct broken_fields_s *bf);

/*destructors*/

/**
 * @param p
 */
void free_broken_m2(gpointer p);

/** @} */

#endif /*OIO_SDS__cluster__conscience__conscience_broken_holder_common_h*/