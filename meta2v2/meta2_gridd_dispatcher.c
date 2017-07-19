/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015-2016 OpenIO, as part of OpenIO Software Defined Storage

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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <glib.h>

#include <server/transport_gridd.h>
#include <server/gridd_dispatcher_filters.h>

#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_gridd_dispatcher.h>
#include <meta2v2/meta2_filters.h>
#include <meta2v2/meta2_filter_context.h>

#define PTR(p) ((gpointer)(p))
#define POS(F) (int)(PTR(F) - PTR(hdata))

static gboolean
meta2_dispatch_all(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	gridd_filter *fl;
	struct gridd_filter_ctx_s *ctx;
	guint loop;

	fl = (gridd_filter*)hdata;
	ctx = meta2_filter_ctx_new();
	meta2_filter_ctx_set_backend(ctx, (struct meta2_backend_s *) gdata);

	if (!fl) {
		GRID_INFO("No filter defined for this request, consider not yet implemented");
		meta2_filter_reply_not_implemented(ctx, reply);
	}
	else {
		for (loop=1; loop && *fl; fl++) {
			switch ((*fl)(ctx, reply)) {
				case FILTER_OK:
					break;
				case FILTER_KO:
					meta2_filter_reply_fail(ctx, reply);
					loop = 0;
					break;
				case FILTER_DONE:
					loop = 0;
					break;
				default:
					meta2_filter_reply_fail(ctx, reply);
					loop = 0;
					break;
			}
		}
	}

	meta2_filter_ctx_clean(ctx);
	return TRUE;
}

/* ------------------------------------------------------------------------- */

static gridd_filter M2V2_CREATE_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_admin,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_events_not_stalled,
	meta2_filter_extract_header_storage_policy,
	meta2_filter_extract_header_version_policy,
	meta2_filter_extract_header_localflag,
	meta2_filter_action_create_container,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_DESTROY_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_admin,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_check_events_not_stalled,
	meta2_filter_action_delete_container,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_EMPTY_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_localflag,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_empty_container,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_HAS_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_localflag,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_has_container,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_PURGE_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_admin,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_action_purge_container,
	NULL
};

static gridd_filter M2V2_DEDUP_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_dedup_contents,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_FLUSH_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_flush_container,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_LIST_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_flags32,
	meta2_filter_extract_list_params,
	meta2_filter_extract_header_localflag,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_list_contents,
	NULL
};

static gridd_filter M2V2_LCHUNK_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_flags32,
	meta2_filter_extract_list_params,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_list_by_chunk_id,
	NULL
};

static gridd_filter M2V2_LHID_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_flags32,
	meta2_filter_extract_list_params,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_list_by_header_id,
	NULL
};

static gridd_filter M2V2_LINK_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_flags32,
	meta2_filter_extract_list_params,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_link,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_LHHASH_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_flags32,
	meta2_filter_extract_list_params,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_list_by_header_hash,
	NULL
};

static gridd_filter M2V2_BEANS_FILTER[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_append,
	meta2_filter_extract_header_spare,
	meta2_filter_extract_header_storage_policy,
	meta2_filter_extract_header_string_size,
	meta2_filter_extract_header_localflag,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_extract_body_beans,
	meta2_filter_action_generate_beans,
	NULL
};

static gridd_filter M2V2_PUT_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_copy,
	meta2_filter_extract_header_optional_overwrite,
	meta2_filter_extract_header_localflag,
	meta2_filter_extract_admin,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_events_not_stalled,
	meta2_filter_extract_body_beans,
	meta2_filter_action_check_content,
	meta2_filter_action_put_content,
	NULL
};

static gridd_filter M2V2_APPEND_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_localflag,
	meta2_filter_extract_admin,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_extract_body_beans,
	meta2_filter_extract_header_storage_policy,
	meta2_filter_action_append_content,
	NULL
};

static gridd_filter M2V2_GET_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_localflag,
	meta2_filter_extract_header_flags32,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_get_content,
	NULL
};

static gridd_filter M2V2_DRAIN_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_admin,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_check_events_not_stalled,
	meta2_filter_action_drain_content,
	NULL,
};

static gridd_filter M2V2_DELETE_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_localflag,
	meta2_filter_extract_header_flags32,
	meta2_filter_extract_admin,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_check_events_not_stalled,
	meta2_filter_action_delete_content,
	NULL
};

static gridd_filter M2V2_TRUNCATE_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_string_size,
	meta2_filter_extract_admin,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_check_events_not_stalled,
	meta2_filter_action_truncate_content,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_PROPSET_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_admin,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_extract_header_flags32,
	meta2_filter_extract_body_beans,
	meta2_filter_check_ns_is_master,
	meta2_filter_action_set_content_properties,
	NULL
};

static gridd_filter M2V2_PROPGET_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_extract_header_flags32,
	meta2_filter_action_get_content_properties,
	NULL
};

static gridd_filter M2V2_PROPDEL_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_del_content_properties,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_EXITELECTION_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_action_exit_election,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_RAW_DEL_filters[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_admin,
	meta2_filter_check_url_cid,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_extract_body_beans,
	meta2_filter_action_delete_beans,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_RAW_ADD_filters[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_admin,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_extract_body_beans,
	meta2_filter_action_insert_beans,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_RAW_SUBST_filters[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_admin,
	meta2_filter_fill_subject,
	meta2_filter_check_url_cid,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_extract_header_chunk_beans,
	meta2_filter_action_update_beans,
	meta2_filter_reply_success,
	NULL
};

/* ------------------------------------------------------------------------- */

static gridd_filter M2V2_FILTERS_touch_content[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_check_url_cid,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_touch_content,
	meta2_filter_reply_success,
	NULL
};

static gridd_filter M2V2_FILTERS_touch_container[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_check_url_cid,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_header_flags32,
	meta2_filter_action_touch_container,
	meta2_filter_reply_success,
	NULL
};

/* ------------------------------------------------------------------------- */

typedef gboolean (*hook) (struct gridd_reply_ctx_s *, gpointer, gpointer);

const struct gridd_request_descr_s *
meta2_gridd_get_v2_requests(void)
{
	/* one-shot features */
	static struct gridd_request_descr_s descriptions[] = {
		/* containers */
		{NAME_MSGNAME_M2V2_CREATE,  (hook) meta2_dispatch_all, M2V2_CREATE_FILTERS},
		{NAME_MSGNAME_M2V2_DESTROY, (hook) meta2_dispatch_all, M2V2_DESTROY_FILTERS},
		{NAME_MSGNAME_M2V2_HAS,	    (hook) meta2_dispatch_all, M2V2_HAS_FILTERS},
		{NAME_MSGNAME_M2V2_ISEMPTY, (hook) meta2_dispatch_all, M2V2_EMPTY_FILTERS},
		{NAME_MSGNAME_M2V2_PURGE,   (hook) meta2_dispatch_all, M2V2_PURGE_FILTERS},
		{NAME_MSGNAME_M2V2_DEDUP,   (hook) meta2_dispatch_all, M2V2_DEDUP_FILTERS},
		{NAME_MSGNAME_M2V2_FLUSH,   (hook) meta2_dispatch_all, M2V2_FLUSH_FILTERS},

		/* contents */
		{NAME_MSGNAME_M2V2_BEANS,   (hook) meta2_dispatch_all, M2V2_BEANS_FILTER},
		{NAME_MSGNAME_M2V2_GET,     (hook) meta2_dispatch_all, M2V2_GET_FILTERS},

		{NAME_MSGNAME_M2V2_PUT,     (hook) meta2_dispatch_all, M2V2_PUT_FILTERS},
		{NAME_MSGNAME_M2V2_LINK,    (hook) meta2_dispatch_all, M2V2_LINK_FILTERS},
		{NAME_MSGNAME_M2V2_APPEND,  (hook) meta2_dispatch_all, M2V2_APPEND_FILTERS},
		{NAME_MSGNAME_M2V2_DRAIN,   (hook) meta2_dispatch_all, M2V2_DRAIN_FILTERS},
		{NAME_MSGNAME_M2V2_DEL,     (hook) meta2_dispatch_all, M2V2_DELETE_FILTERS},
		{NAME_MSGNAME_M2V2_TRUNC,   (hook) meta2_dispatch_all, M2V2_TRUNCATE_FILTERS},

		{NAME_MSGNAME_M2V2_LIST,    (hook) meta2_dispatch_all, M2V2_LIST_FILTERS},
		{NAME_MSGNAME_M2V2_LCHUNK,  (hook) meta2_dispatch_all, M2V2_LCHUNK_FILTERS},
		{NAME_MSGNAME_M2V2_LHHASH,  (hook) meta2_dispatch_all, M2V2_LHHASH_FILTERS},
		{NAME_MSGNAME_M2V2_LHID,    (hook) meta2_dispatch_all, M2V2_LHID_FILTERS},

		/* content properties (container properties now managed through
		 * sqlx queries) */
		{NAME_MSGNAME_M2V2_PROP_SET, (hook) meta2_dispatch_all, M2V2_PROPSET_FILTERS},
		{NAME_MSGNAME_M2V2_PROP_GET, (hook) meta2_dispatch_all, M2V2_PROPGET_FILTERS},
		{NAME_MSGNAME_M2V2_PROP_DEL, (hook) meta2_dispatch_all, M2V2_PROPDEL_FILTERS},

		/* raw beans */
		{NAME_MSGNAME_M2V2_RAW_DEL,   (hook) meta2_dispatch_all, M2V2_RAW_DEL_filters},
		{NAME_MSGNAME_M2V2_RAW_ADD,   (hook) meta2_dispatch_all, M2V2_RAW_ADD_filters},
		{NAME_MSGNAME_M2V2_RAW_SUBST, (hook) meta2_dispatch_all, M2V2_RAW_SUBST_filters},

		{NAME_MSGNAME_M2V2_EXITELECTION, (hook) meta2_dispatch_all,  M2V2_EXITELECTION_FILTERS},

		/* AGENT EVENTS */
		{NAME_MSGNAME_M2V1_TOUCH_CONTAINER, (hook) meta2_dispatch_all, M2V2_FILTERS_touch_container},
		{NAME_MSGNAME_M2V1_TOUCH_CONTENT,   (hook) meta2_dispatch_all, M2V2_FILTERS_touch_content},

		{NULL, NULL, NULL}
	};

	return descriptions;
}

