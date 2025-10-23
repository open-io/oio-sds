/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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

#ifndef OIO_SDS__meta2v2__meta2_filters_h
# define OIO_SDS__meta2v2__meta2_filters_h 1

#define TRACE_FILTER()

struct gridd_filter_ctx_s;
struct gridd_reply_ctx_s;
struct meta2_backend_s;
struct oio_events_queue_s;

struct on_bean_ctx_s
{
	GSList *l;
	gboolean first;
	struct gridd_reply_ctx_s *reply;
	struct gridd_filter_ctx_s *ctx;
};

struct async_repli_s
{
	const char *dests;
	const char *replicator_id;
	const char *role_project_id;
	GSList *props;
};

struct on_bean_ctx_s *_on_bean_ctx_init(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply);

void _on_bean_ctx_send_list(struct on_bean_ctx_s *obc);

void _on_bean_ctx_clean(struct on_bean_ctx_s *obc);

void _m2b_notify_beans(
		struct oio_events_queue_s *notifier,
		struct oio_url_s *url,
		GSList *beans, const char *name, gboolean send_chunks);

void _m2b_notify_beans2(
		struct oio_events_queue_s *notifier,
		struct oio_url_s *url,
		GSList *beans, const char *name, gboolean send_chunks,
		struct async_repli_s *repli);

// Replication functions
struct async_repli_s *_async_repli_init(struct gridd_filter_ctx_s *ctx);
void _async_repli_clean(struct async_repli_s *repli);
GError* _m2b_extract_repli_properties(struct gridd_filter_ctx_s *ctx, GSList **out);
void meta2_json_encode_async_repli(GString *g, struct async_repli_s *repli);

/* -------------------------------------------------------------------------- */

#define M2V2_DECLARE_FILTER(F) int F (struct gridd_filter_ctx_s *, struct gridd_reply_ctx_s *)

M2V2_DECLARE_FILTER(meta2_filter_check_url_cid);
M2V2_DECLARE_FILTER(meta2_filter_check_ns_name);
M2V2_DECLARE_FILTER(meta2_filter_check_optional_ns_name);
M2V2_DECLARE_FILTER(meta2_filter_check_backend);
M2V2_DECLARE_FILTER(meta2_filter_check_events_not_stalled);
/** Check that the requested region matches the region we are in. */
M2V2_DECLARE_FILTER(meta2_filter_check_region);

M2V2_DECLARE_FILTER(meta2_filter_extract_header_url);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_chunk_beans);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_storage_policy);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_version_policy);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_peers);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_spare);
M2V2_DECLARE_FILTER(meta2_filter_extract_body_beans);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_localflag);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_flags32);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_string_size);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_optional_delete_marker);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_optional_bypass_governance);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_optional_dryrun);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_optional_overwrite);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_optional_slo_manifest);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_string_maxvers);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_optional_async_replication);
M2V2_DECLARE_FILTER(meta2_filter_extract_list_params);
M2V2_DECLARE_FILTER(meta2_filter_extract_limit);
M2V2_DECLARE_FILTER(meta2_filter_extract_force_master);
M2V2_DECLARE_FILTER(meta2_filter_extract_user_agent);
M2V2_DECLARE_FILTER(meta2_filter_extract_force_versioning);
M2V2_DECLARE_FILTER(meta2_filter_extract_find_shards_params);
M2V2_DECLARE_FILTER(meta2_filter_extract_prepare_shard_params);
M2V2_DECLARE_FILTER(meta2_filter_extract_region);
M2V2_DECLARE_FILTER(meta2_filter_extract_sharding_info);
M2V2_DECLARE_FILTER(meta2_filter_extract_prefix);
M2V2_DECLARE_FILTER(meta2_filter_extract_suffix);
M2V2_DECLARE_FILTER(meta2_filter_extract_lifecycle_action_params);

M2V2_DECLARE_FILTER(meta2_filter_fill_subject);
M2V2_DECLARE_FILTER(meta2_filter_reply_success);
M2V2_DECLARE_FILTER(meta2_filter_reply_fail);
M2V2_DECLARE_FILTER(meta2_filter_reply_not_implemented);

M2V2_DECLARE_FILTER(meta2_filter_action_create_container);
M2V2_DECLARE_FILTER(meta2_filter_action_empty_container);
M2V2_DECLARE_FILTER(meta2_filter_action_delete_container);
M2V2_DECLARE_FILTER(meta2_filter_action_purge_container);
M2V2_DECLARE_FILTER(meta2_filter_action_flush_container);
M2V2_DECLARE_FILTER(meta2_filter_action_drain_container);
M2V2_DECLARE_FILTER(meta2_filter_action_checkpoint);
M2V2_DECLARE_FILTER(meta2_filter_action_list_contents);
M2V2_DECLARE_FILTER(meta2_filter_action_list_by_chunk_id);
M2V2_DECLARE_FILTER(meta2_filter_action_list_by_header_id);
M2V2_DECLARE_FILTER(meta2_filter_action_list_by_header_hash);
M2V2_DECLARE_FILTER(meta2_filter_action_put_content);
M2V2_DECLARE_FILTER(meta2_filter_action_request_policy_transition);
M2V2_DECLARE_FILTER(meta2_filter_action_append_content);
M2V2_DECLARE_FILTER(meta2_filter_action_check_content);
M2V2_DECLARE_FILTER(meta2_filter_action_get_content);
M2V2_DECLARE_FILTER(meta2_filter_action_drain_content);
M2V2_DECLARE_FILTER(meta2_filter_action_delete_content);
M2V2_DECLARE_FILTER(meta2_filter_action_truncate_content);
M2V2_DECLARE_FILTER(meta2_filter_action_set_content_properties);
M2V2_DECLARE_FILTER(meta2_filter_action_get_content_properties);
M2V2_DECLARE_FILTER(meta2_filter_action_del_content_properties);
M2V2_DECLARE_FILTER(meta2_filter_action_generate_beans);
M2V2_DECLARE_FILTER(meta2_filter_action_touch_content);
M2V2_DECLARE_FILTER(meta2_filter_action_purge_content);
M2V2_DECLARE_FILTER(meta2_filter_action_touch_container);
M2V2_DECLARE_FILTER(meta2_filter_action_insert_beans);
M2V2_DECLARE_FILTER(meta2_filter_action_delete_beans);
M2V2_DECLARE_FILTER(meta2_filter_action_update_beans);
M2V2_DECLARE_FILTER(meta2_filter_action_find_shards);
M2V2_DECLARE_FILTER(meta2_filter_action_get_shards_in_range);
M2V2_DECLARE_FILTER(meta2_filter_action_prepare_sharding);
M2V2_DECLARE_FILTER(meta2_filter_action_merge_sharding);
M2V2_DECLARE_FILTER(meta2_filter_action_update_shard);
M2V2_DECLARE_FILTER(meta2_filter_action_lock_sharding);
M2V2_DECLARE_FILTER(meta2_filter_action_replace_sharding);
M2V2_DECLARE_FILTER(meta2_filter_action_clean_sharding);
M2V2_DECLARE_FILTER(meta2_filter_action_show_sharding);
M2V2_DECLARE_FILTER(meta2_filter_action_abort_sharding);
M2V2_DECLARE_FILTER(meta2_filter_action_create_lifecycle_views);
M2V2_DECLARE_FILTER(meta2_filter_action_apply_lifecycle);

M2V2_DECLARE_FILTER(meta2_filter_action_exit_election);

#endif /*OIO_SDS__meta2v2__meta2_filters_h*/
