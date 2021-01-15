/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

struct on_bean_ctx_s *_on_bean_ctx_init(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply);

void _on_bean_ctx_send_list(struct on_bean_ctx_s *obc);

void _on_bean_ctx_clean(struct on_bean_ctx_s *obc);

void _m2b_notify_beans(
		struct oio_events_queue_s *notifier,
		struct oio_url_s *url,
		GSList *beans, const char *name, gboolean send_chunks);

/* -------------------------------------------------------------------------- */

#define M2V2_DECLARE_FILTER(F) int F (struct gridd_filter_ctx_s *, struct gridd_reply_ctx_s *)

M2V2_DECLARE_FILTER(meta2_filter_check_url_cid);
M2V2_DECLARE_FILTER(meta2_filter_check_ns_name);
M2V2_DECLARE_FILTER(meta2_filter_check_optional_ns_name);
M2V2_DECLARE_FILTER(meta2_filter_check_backend);
M2V2_DECLARE_FILTER(meta2_filter_check_ns_is_master);
M2V2_DECLARE_FILTER(meta2_filter_check_ns_not_wormed);
M2V2_DECLARE_FILTER(meta2_filter_check_events_not_stalled);

M2V2_DECLARE_FILTER(meta2_filter_extract_header_url);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_chunk_beans);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_storage_policy);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_version_policy);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_peers);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_spare);
M2V2_DECLARE_FILTER(meta2_filter_extract_body_beans);
M2V2_DECLARE_FILTER(meta2_filter_extract_body_strings);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_localflag);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_flags32);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_append);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_string_size);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_optional_delete_marker);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_optional_overwrite);
M2V2_DECLARE_FILTER(meta2_filter_extract_header_string_maxvers);
M2V2_DECLARE_FILTER(meta2_filter_extract_list_params);
M2V2_DECLARE_FILTER(meta2_filter_extract_admin);
M2V2_DECLARE_FILTER(meta2_filter_extract_force_master);
M2V2_DECLARE_FILTER(meta2_filter_extract_user_agent);
M2V2_DECLARE_FILTER(meta2_filter_extract_force_versioning);
M2V2_DECLARE_FILTER(meta2_filter_extract_simulate_versioning);

M2V2_DECLARE_FILTER(meta2_filter_fill_subject);
M2V2_DECLARE_FILTER(meta2_filter_reply_success);
M2V2_DECLARE_FILTER(meta2_filter_reply_fail);
M2V2_DECLARE_FILTER(meta2_filter_reply_not_implemented);

M2V2_DECLARE_FILTER(meta2_filter_action_create_container);
M2V2_DECLARE_FILTER(meta2_filter_action_empty_container);
M2V2_DECLARE_FILTER(meta2_filter_action_has_container);
M2V2_DECLARE_FILTER(meta2_filter_action_delete_container);
M2V2_DECLARE_FILTER(meta2_filter_action_purge_container);
M2V2_DECLARE_FILTER(meta2_filter_action_flush_container);
M2V2_DECLARE_FILTER(meta2_filter_action_list_contents);
M2V2_DECLARE_FILTER(meta2_filter_action_list_by_chunk_id);
M2V2_DECLARE_FILTER(meta2_filter_action_list_by_header_id);
M2V2_DECLARE_FILTER(meta2_filter_action_list_by_header_hash);
M2V2_DECLARE_FILTER(meta2_filter_action_put_content);
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
M2V2_DECLARE_FILTER(meta2_filter_action_replace_container_sharding);
M2V2_DECLARE_FILTER(meta2_filter_action_show_container_sharding);

M2V2_DECLARE_FILTER(meta2_filter_action_exit_election);

#endif /*OIO_SDS__meta2v2__meta2_filters_h*/
