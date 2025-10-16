/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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

#ifndef OIO_SDS__meta2v2__meta2v2_remote_h
# define OIO_SDS__meta2v2__meta2v2_remote_h 1

# include <glib.h>
# include <meta2v2/autogen.h>


struct oio_url_s;

struct list_params_s;

struct list_result_s
{
	GSList *beans;
	GTree *props;
	gchar *next_marker;
	gchar *next_version_marker;
	gboolean truncated;
};

void m2v2_list_result_init (struct list_result_s *p);
void m2v2_list_result_clean (struct list_result_s *p);

/* Extract a list of beans from a meta2 response. Beans are stored
 * in a (struct list_result_s *) cast from ctx. */
gboolean m2v2_list_result_extract(gpointer ctx, guint status, MESSAGE reply);
gboolean m2v2_boolean_truncated_extract(gpointer ctx, guint status,
		MESSAGE reply);

gboolean m2v2_offset_extract(gpointer ctx, guint status, MESSAGE reply);
struct m2v2_create_params_s;

/* deadline known from thread-local */
GError* m2v2_remote_execute_DESTROY(
		const char *target,
		struct oio_url_s *url,
		guint32 flags);

GByteArray* m2v2_remote_pack_container_DRAIN(
		struct oio_url_s *url,
		const char *limit_str,
		gint64 deadline);

/* deadline known from thread-local
 * Locally destroy a container on several services. */
GError* m2v2_remote_execute_DESTROY_many(
		gchar **targets,
		struct oio_url_s *url,
		guint32 flags);

GByteArray* m2v2_remote_pack_CREATE(
		struct oio_url_s *url,
		struct m2v2_create_params_s *pols,
		const gchar **headers,
		gint64 deadline);

GByteArray* m2v2_remote_pack_DESTROY(
		struct oio_url_s *url,
		guint32 flags,
		gint64 deadline);

GByteArray* m2v2_remote_pack_ISEMPTY(
		struct oio_url_s *url,
		gint64 deadline);

GByteArray* m2v2_remote_pack_FLUSH(
		struct oio_url_s *url,
		gint64 deadline);

GByteArray* m2v2_remote_pack_PURGEC(
		struct oio_url_s *url,
		const char *maxvers_str,
		gint64 deadline);

GByteArray* m2v2_remote_pack_PURGEB(
		struct oio_url_s *url,
		const char *maxvers_str,
		gint64 deadline);

GByteArray* m2v2_remote_pack_DEDUP(
		struct oio_url_s *url,
		gint64 deadline);

GByteArray* m2v2_remote_pack_PUT(
		struct oio_url_s *url,
		GSList *beans,
		const char *destinations,
		const char *replicator_id,
		const char *role_project_id,
		gint64 deadline);

GByteArray* m2v2_remote_pack_OVERWRITE(
		struct oio_url_s *url,
		GSList *beans,
		gint64 deadline);

GByteArray* m2v2_remote_pack_UPDATE(
		struct oio_url_s *url,
		GSList *beans,
		gint64 deadline);

GByteArray* m2v2_remote_pack_CHANGE_POLICY(
		struct oio_url_s *url,
		GSList *beans,
		gint64 deadline);

GByteArray* m2v2_remote_pack_POLICY_TRANSITION(
		struct oio_url_s *url,
		const gchar *policy,
		gboolean skip_data_move,
		gboolean internal_transition,
		gint64 deadline);

GByteArray* m2v2_remote_pack_RESTORE_DRAINED(
		struct oio_url_s *url,
		GSList *beans,
		gint64 deadline);

GByteArray* m2v2_remote_pack_APPEND(
		struct oio_url_s *url,
		GSList *beans,
		gint64 deadline);

GByteArray* m2v2_remote_pack_content_DRAIN(
		struct oio_url_s *url,
		gint64 deadline);

GByteArray* m2v2_remote_pack_CHECKPOINT(
		struct oio_url_s *url,
		const char* suffix,
		gint64 dl);

GByteArray* m2v2_remote_pack_DEL(
		struct oio_url_s *url,
		gboolean bypass_governance,
		gboolean create_delete_marker,
		gboolean dryrun,
		gboolean slo_manifest,
		const char *destinations,
		const char *replicator_id,
		const char *role_project_id,
		gint64 deadline);

GByteArray* m2v2_remote_pack_TRUNC(
		struct oio_url_s *url,
		gint64 size,
		gint64 deadline);

GByteArray* m2v2_remote_pack_GET(
		struct oio_url_s *url,
		guint32 flags,
		gint64 deadline);

GByteArray* m2v2_remote_pack_LIST(
		struct oio_url_s *url,
		struct list_params_s *p,
		gint64 deadline);

GByteArray* m2v2_remote_pack_LIST_BY_CHUNKID(
		struct oio_url_s *url,
		struct list_params_s *p,
		const char *chunk,
		gint64 deadline);

GByteArray* m2v2_remote_pack_LIST_BY_HEADERHASH(
		struct oio_url_s *url,
		struct list_params_s *p,
		GBytes *h,
		gint64 deadline);

GByteArray* m2v2_remote_pack_LIST_BY_HEADERID(
		struct oio_url_s *url,
		struct list_params_s *p,
		GBytes *h,
		gint64 deadline);

GByteArray* m2v2_remote_pack_RAW_DEL(
		struct oio_url_s *url,
		GSList *beans,
		gint64 deadline);

GByteArray* m2v2_remote_pack_RAW_ADD(
		struct oio_url_s *url,
		GSList *beans,
		gboolean frozen,
		gboolean force,
		gint64 deadline);

GByteArray* m2v2_remote_pack_RAW_SUBST(
		struct oio_url_s *url,
		GSList *new_chunks,
		GSList *old_chunks,
		gboolean frozen,
		gint64 deadline);

GByteArray* m2v2_remote_pack_PROP_DEL(
		struct oio_url_s *url,
		gchar **names,
		const char *destinations,
		const char *replicator_id,
		const char *role_project_id,
		gint64 deadline);

GByteArray* m2v2_remote_pack_PROP_SET(
		struct oio_url_s *url,
		guint32 flags,
		GSList *beans,
		const char *destinations,
		const char *replicator_id,
		const char *role_project_id,
		gint64 deadline);

GByteArray* m2v2_remote_pack_PROP_GET(
		struct oio_url_s *url,
		gint64 deadline);

GByteArray* m2v2_remote_pack_TOUCHB(
		struct oio_url_s *url,
		guint32 flags,
		gint64 deadline,
		gboolean recompute);

GByteArray* m2v2_remote_pack_TOUCHC(
		struct oio_url_s *url,
		gint64 deadline);

GByteArray* m2v2_remote_pack_FIND_SHARDS(
		struct oio_url_s *url,
		const gchar* strategy,
		GByteArray *strategy_params,
		gint64 dl);

GByteArray* m2v2_remote_pack_PREPARE_SHARDING(
		struct oio_url_s *url,
		const gchar* action,
		GSList *beans,
		gint64 dl);

GByteArray* m2v2_remote_pack_MERGE_SHARDING(
		struct oio_url_s *url,
		GSList *beans,
		gint64 dl);

GByteArray* m2v2_remote_pack_UPDATE_SHARD(
		struct oio_url_s *url,
		gchar **queries,
		gint64 dl);

GByteArray* m2v2_remote_pack_LOCK_SHARDING(
		struct oio_url_s *url,
		gint64 dl);

GByteArray* m2v2_remote_pack_REPLACE_SHARDING(
		struct oio_url_s *url,
		GSList *beans,
		gint64 dl);

GByteArray* m2v2_remote_pack_CLEAN_SHARDING(
		struct oio_url_s *url,
		GSList *beans,
		gboolean local,
		gboolean urgent,
		gint64 dl);

GByteArray* m2v2_remote_pack_SHOW_SHARDING(
		struct oio_url_s *url,
		struct list_params_s *params,
		gint64 dl);

GByteArray* m2v2_remote_pack_ABORT_SHARDING(
		struct oio_url_s *url,
		gint64 dl);

GByteArray* m2v2_remote_pack_GET_SHARDS_IN_RANGE(
	struct oio_url_s *url,
	GByteArray *bounds_params,
	gint64 dl);
GByteArray* m2v2_remote_pack_CREATE_LIFECYCLE_VIEWS(
		struct oio_url_s *url,
        GByteArray *params,
		gint64 dl);

GByteArray* m2v2_remote_pack_APPLY_LIFECYCLE(
		struct oio_url_s *url,
		const gchar *action_type,
        GByteArray *params,
		gint64 dl);

#endif /*OIO_SDS__meta2v2__meta2v2_remote_h*/
