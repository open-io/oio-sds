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

#ifndef OIO_SDS__meta2v2__meta2_filters_h
# define OIO_SDS__meta2v2__meta2_filters_h 1

#define M2V2_DECLARE_FILTER(F) int F (struct gridd_filter_ctx_s *, struct gridd_reply_ctx_s *)

struct gridd_filter_ctx_s
{
	struct meta2_backend_s *backend;
	struct m2op_target_s base;
	gboolean flag_admin;
};

int _reply_no_body(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply, GError *err);

int _reply_beans_and_clean(struct gridd_reply_ctx_s *reply, GSList *beans);

M2V2_DECLARE_FILTER(meta2_filter_action_create_container);
M2V2_DECLARE_FILTER(meta2_filter_action_empty_container);
M2V2_DECLARE_FILTER(meta2_filter_action_has_container);
M2V2_DECLARE_FILTER(meta2_filter_action_delete_container);
M2V2_DECLARE_FILTER(meta2_filter_action_purge_container);
M2V2_DECLARE_FILTER(meta2_filter_action_dedup_contents);
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
M2V2_DECLARE_FILTER(meta2_filter_action_link);
M2V2_DECLARE_FILTER(meta2_filter_action_set_content_properties);
M2V2_DECLARE_FILTER(meta2_filter_action_get_content_properties);
M2V2_DECLARE_FILTER(meta2_filter_action_del_content_properties);
M2V2_DECLARE_FILTER(meta2_filter_action_generate_beans);
M2V2_DECLARE_FILTER(meta2_filter_action_touch_content);

#define META2TOUCH_FLAGS_UPDATECSIZE     0x00000001
#define META2TOUCH_FLAGS_RECALCCSIZE     0x00000002
M2V2_DECLARE_FILTER(meta2_filter_action_touch_container);
M2V2_DECLARE_FILTER(meta2_filter_action_insert_beans);
M2V2_DECLARE_FILTER(meta2_filter_action_delete_beans);
M2V2_DECLARE_FILTER(meta2_filter_action_update_beans);

M2V2_DECLARE_FILTER(meta2_filter_action_exit_election);

#endif /*OIO_SDS__meta2v2__meta2_filters_h*/
