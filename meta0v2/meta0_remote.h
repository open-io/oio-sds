/*
OpenIO SDS meta0v2
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

#ifndef OIO_SDS__meta0v2__meta0_remote_h
# define OIO_SDS__meta0v2__meta0_remote_h 1

/**
 * @addtogroup meta0v2_remote
 * @{
 */

#include <glib.h>

#include <metautils/lib/metatypes.h>

/** The request name when requesting the whole meta0 cache */
#define NAME_MSGNAME_M0_GETALL "REQ_M0_GETALL"

/** The request name when requesting only one meta0 entry */
#define NAME_MSGNAME_M0_GETONE "REQ_M0_GETONE"

/** The request name when requesting a server reload */
#define NAME_MSGNAME_M0_RELOAD "REQ_M0_RELOAD"

/** The request name when requesting a server init */
#define NAME_MSGNAME_M0_FILL "REQ_M0_FILL"

/** The request name when requesting a server init, version 2 */
#define NAME_MSGNAME_M0_V2_FILL "REQ_M0_V2_FILL"

/** The request name when requesting a reallocation of meta1 through all prefixes */
#define NAME_MSGNAME_M0_ASSIGN "REQ_M0_V2_ASSIGN_PREFIX"

/** The request name when requesting to disable meta1 services from prefix repartition */
#define NAME_MSGNAME_M0_DISABLE_META1 "REQ_M0_V2_DISABLE_META1"

/** The request name when requestingthe whole meta1 information */
#define NAME_MSGNAME_M0_GET_META1_INFO "REQ_M0_V2_GETMETA1INFO"

/** The request name when requesting to destroy the reférence of meta1 service, only if meta1 service is disable */
#define NAME_MSGNAME_M0_DESTROY_META1REF "REQ_M0_V2_DESTROY_META1REF"

/** The request name when requesting to destroy the zookeepeer node referencing the meta0 */
#define NAME_MSGNAME_M0_DESTROY_META0ZKNODE "REQ_M0_V2_DESTROY_META0ZKNODE"

/**
 * Fill the pointed hash table with a full representation of the
 * reference Meta0 hash table.
 *
 * Keys are the addresses of the pointed META1, values are pointers 
 * to meta0info_t structures. In these meta0_info_t structures, the
 * address field is the adress pointed by the key, and the prefix is
 * a byte array whose length is multiple of 2, and each pair of bytes
 * is a container ID prefix.
 *
 * There is no retry feature and no cache feature in this function.
 *
 * @param m0a the address of the remote meta0 reference server
 * @param ms the maximum number of times (in milli seconds) this operations
 *           should take in network latencies.
 * @param err a pointer to the error structure. It will be set if the
 *            function fails
 * @return  a GSList of meta0_info_t
 */
GSList *meta0_remote_get_meta1_all(addr_info_t *m0a, gint ms, GError **err);

/** */
GSList *meta0_remote_get_meta1_one(addr_info_t *m0a, gint ms,
		const guint8 *prefix, GError **err);

gint meta0_remote_cache_refresh(addr_info_t *m0a, gint ms, GError **err);

gint meta0_remote_fill(addr_info_t *m0a, gint ms, gchar **urls,
		guint nbreplicas, GError **err);

gint meta0_remote_fill_v2(addr_info_t *m0a, gint ms, guint nbreplicas,
		gboolean nodist, GError **err);

gint meta0_remote_assign(addr_info_t *m0a, gint ms, gboolean nocheck,GError **err);

gint meta0_remote_disable_meta1(addr_info_t *m0a, gint ms, gchar **urls,
		 gboolean nocheck, GError **err);

gchar ** meta0_remote_get_meta1_info(addr_info_t *m0a, gint ms, GError **err);

gint meta0_remote_destroy_meta1ref(addr_info_t *m0a, gint ms, gchar *urls, GError **err);

gint meta0_remote_destroy_meta0zknode(addr_info_t *m0a, gint ms, gchar *urls, GError **err);

/** @} */

#endif /*OIO_SDS__meta0v2__meta0_remote_h*/
