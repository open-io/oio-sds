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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>
#include <cluster/lib/gridcluster.h>
#include <events/oio_events_queue.h>
#include <resolver/hc_resolver.h>
#include <server/transport_gridd.h>
#include <server/gridd_dispatcher_filters.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/meta2_backend.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_filters.h>
#include <meta2v2/meta2_gridd_dispatcher.h>

#define PTR(p) ((gpointer)(p))
#define POS(F) (int)(PTR(F) - PTR(hdata))

int
_reply_beans_and_clean(struct gridd_reply_ctx_s *reply, GSList *beans)
{
	beans = g_slist_reverse (beans);
	reply->add_body(bean_sequence_marshall(beans));
	_bean_cleanl2 (beans);
	reply->send_reply(CODE_FINAL_OK, "OK");
	return FILTER_OK;
}

int
_reply_no_body(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply, GError *err)
{
	if (!err) {
		reply->send_reply(CODE_FINAL_OK, "OK");
		return FILTER_OK;
	}

	if (err->code == CODE_CONTAINER_NOTFOUND)
		hc_decache_reference_service(ctx->backend->resolver,
				ctx->base.url, NAME_SRVTYPE_META2);

	reply->send_error(0, err);
	return FILTER_KO;
}

static int
meta2_filter_check_path(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	if (oio_url_has(ctx->base.url, OIOURL_PATH) ||
			oio_url_has(ctx->base.url, OIOURL_CONTENTID))
		return FILTER_OK;
	_reply_no_body(ctx, reply, BADREQ("Invalid URL"));
	return FILTER_KO;
}

static int
meta2_filter_check_ns_is_master(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	if (ctx->flag_admin)
		return FILTER_OK;

	if (!oio_ns_master)
		return _reply_no_body(ctx, reply, SYSERR("Slave NS"));
	return FILTER_OK;
}

static int
meta2_filter_check_ns_not_wormed(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	if (ctx->flag_admin)
		return FILTER_OK;

	if (oio_ns_mode_worm)
		return _reply_no_body(ctx, reply, SYSERR("WORM NS"));
	return FILTER_OK;
}

static int
meta2_filter_check_events_not_stalled (struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	if (ctx->backend->notifier &&
			oio_events_queue__is_stalled (ctx->backend->notifier))
			return _reply_no_body(ctx, reply, BUSY("Too many pending events"));

	return FILTER_OK;
}

static gboolean
meta2_dispatch_all(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	EXTRA_ASSERT(gdata != NULL);
	EXTRA_ASSERT(hdata != NULL);

	/* init the context with some fields common to any RPC */
	struct gridd_filter_ctx_s ctx = {0};
	ctx.backend = gdata;

	ctx.base.url = metautils_message_extract_url(reply->request);
	ctx.flag_admin = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_ADMIN_COMMAND, FALSE);
	ctx.base.flag_master_only = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_MASTER, FALSE);
	ctx.base.flag_local = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_LOCAL, FALSE);

	/* TODO FIXME transitonal code, turn ASAP the default to FALSE */
	ctx.base.flag_last_base = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_LAST, TRUE);

	reply->subject("%s|%s",
			oio_url_get(ctx.base.url, OIOURL_WHOLE),
			oio_url_get(ctx.base.url, OIOURL_HEXID));

	/* With the addition of the sharding of containers, the sequence
	 * number of the shard must be set to a positive value. No quirk
	 * to mannage backward compliance here, this would be too error-prone */
	GError *err = NULL;
	if (!err) {
		err = metautils_message_extract_strint64(reply->request,
				NAME_MSGKEY_SEQNUM, &ctx.base.seq);
		/* TODO FIXME transitional code, remove ASAP */
		if (err && err->code == CODE_BAD_REQUEST) {
			g_clear_error(&err);
			ctx.base.seq = 1;
		}
	}

	if (!err && ctx.base.seq < 1)
		err = BADREQ("Invalid sequence number");
	if (err) {
		_reply_no_body(&ctx, reply, err);
		goto exit;
	}

	/* checks common to any RPC */
	if (!meta2_backend_initiated(ctx.backend)) {
		_reply_no_body(&ctx, reply, SYSERR("Backend not ready"));
		goto exit;
	}
	if (!oio_url_has(ctx.base.url, OIOURL_HEXID)) {
		_reply_no_body(&ctx, reply, BADREQ("Missing container ID"));
		goto exit;
	}
	if (oio_url_has(ctx.base.url, OIOURL_NS)) {
		if (0 != strcmp(oio_url_get(ctx.base.url, OIOURL_NS), ctx.backend->ns_name)) {
			_reply_no_body(&ctx, reply, BADNS());
			goto exit;
		}
	}

	/* Now apply the filters */
	for (gridd_filter *fl = (gridd_filter*)hdata; *fl; fl++) {
		if (FILTER_OK != (*fl)(&ctx, reply))
			break;
	}

exit:
	oio_url_pclean(&ctx.base.url);
	return TRUE;
}

/* ------------------------------------------------------------------------- */

static gridd_filter M2V2_CREATE_FILTERS[] =
{
	meta2_filter_check_ns_is_master,
	meta2_filter_check_events_not_stalled,
	meta2_filter_action_create_container,
	NULL
};

static gridd_filter M2V2_DESTROY_FILTERS[] =
{
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_check_events_not_stalled,
	meta2_filter_action_delete_container,
	NULL
};

static gridd_filter M2V2_EMPTY_FILTERS[] =
{
	meta2_filter_action_empty_container,
	NULL
};

static gridd_filter M2V2_HAS_FILTERS[] =
{
	meta2_filter_action_has_container,
	NULL
};

static gridd_filter M2V2_PURGE_FILTERS[] =
{
	meta2_filter_check_ns_is_master,
	meta2_filter_action_purge_container,
	NULL
};

static gridd_filter M2V2_DEDUP_FILTERS[] =
{
	meta2_filter_action_dedup_contents,
	NULL
};

static gridd_filter M2V2_FLUSH_FILTERS[] =
{
	meta2_filter_action_flush_container,
	NULL
};

static gridd_filter M2V2_LIST_FILTERS[] =
{
	meta2_filter_action_list_contents,
	NULL
};

static gridd_filter M2V2_LCHUNK_FILTERS[] =
{
	meta2_filter_action_list_by_chunk_id,
	NULL
};

static gridd_filter M2V2_LHID_FILTERS[] =
{
	meta2_filter_action_list_by_header_id,
	NULL
};

static gridd_filter M2V2_LINK_FILTERS[] =
{
	meta2_filter_check_path,
	meta2_filter_action_link,
	NULL
};

static gridd_filter M2V2_LHHASH_FILTERS[] =
{
	meta2_filter_action_list_by_header_hash,
	NULL
};

static gridd_filter M2V2_BEANS_FILTER[] =
{
	meta2_filter_action_generate_beans,
	NULL
};

static gridd_filter M2V2_PUT_FILTERS[] =
{
	meta2_filter_check_path,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_events_not_stalled,
	meta2_filter_action_put_content,
	NULL
};

static gridd_filter M2V2_APPEND_FILTERS[] =
{
	meta2_filter_check_path,
	meta2_filter_check_ns_is_master,
	meta2_filter_action_append_content,
	NULL
};

static gridd_filter M2V2_GET_FILTERS[] =
{
	meta2_filter_check_path,
	meta2_filter_action_get_content,
	NULL
};

static gridd_filter M2V2_DRAIN_FILTERS[] =
{
	meta2_filter_check_path,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_check_events_not_stalled,
	meta2_filter_action_drain_content,
	NULL,
};

static gridd_filter M2V2_DELETE_FILTERS[] =
{
	meta2_filter_check_path,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_check_events_not_stalled,
	meta2_filter_action_delete_content,
	NULL
};

static gridd_filter M2V2_TRUNCATE_FILTERS[] =
{
	meta2_filter_check_path,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_check_events_not_stalled,
	meta2_filter_action_truncate_content,
	NULL
};

static gridd_filter M2V2_PROPSET_FILTERS[] =
{
	meta2_filter_check_path,
	meta2_filter_check_ns_is_master,
	meta2_filter_action_set_content_properties,
	NULL
};

static gridd_filter M2V2_PROPGET_FILTERS[] =
{
	meta2_filter_check_path,
	meta2_filter_action_get_content_properties,
	NULL
};

static gridd_filter M2V2_PROPDEL_FILTERS[] =
{
	meta2_filter_check_path,
	meta2_filter_action_del_content_properties,
	NULL
};

static gridd_filter M2V2_RAW_DEL_filters[] =
{
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_delete_beans,
	NULL
};

static gridd_filter M2V2_RAW_ADD_filters[] =
{
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_insert_beans,
	NULL
};

static gridd_filter M2V2_RAW_SUBST_filters[] =
{
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_update_beans,
	NULL
};

/* ------------------------------------------------------------------------- */

static gridd_filter M2V2_FILTERS_touch_content[] =
{
	meta2_filter_check_path,
	meta2_filter_action_touch_content,
	NULL
};

static gridd_filter M2V2_FILTERS_touch_container[] =
{
	meta2_filter_action_touch_container,
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

		/* AGENT EVENTS */
		{NAME_MSGNAME_M2V1_TOUCH_CONTAINER, (hook) meta2_dispatch_all, M2V2_FILTERS_touch_container},
		{NAME_MSGNAME_M2V1_TOUCH_CONTENT,   (hook) meta2_dispatch_all, M2V2_FILTERS_touch_content},

		{NULL, NULL, NULL}
	};

	return descriptions;
}

