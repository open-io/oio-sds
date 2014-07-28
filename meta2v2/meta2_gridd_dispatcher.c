#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2.disp"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <glib.h>

#include <meta2/remote/meta2_remote.h>

#include <server/grid_daemon.h>
#include <server/transport_gridd.h>
#include <server/gridd_dispatcher_filters.h>

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
		meta2_filter_not_implemented_reply(ctx, reply);
	}
	else {
		for (loop=1; loop && *fl; fl++) {
			switch ((*fl)(ctx, reply)) {
				case FILTER_OK:
					break;
				case FILTER_KO:
					meta2_filter_fail_reply(ctx, reply);
					loop = 0;
					break;
				case FILTER_DONE:
					loop = 0;
					break;
				default:
					meta2_filter_fail_reply(ctx, reply);
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
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_is_writable,
	meta2_filter_extract_header_storage_policy,
	meta2_filter_extract_header_version_policy,
	meta2_filter_extract_header_localflag,
	meta2_filter_action_create_container,
	meta2_filter_success_reply,
	meta2_filter_action_notify_container_CREATE,
	NULL
};

static gridd_filter M2V2_DESTROY_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_forceflag,
	meta2_filter_extract_header_purgeflag,
	meta2_filter_extract_header_flushflag,
	meta2_filter_extract_header_localflag,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_delete_container,
	meta2_filter_success_reply,
	meta2_filter_action_notify_container_DESTROY,
	NULL
};

static gridd_filter M2V2_HAS_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_action_has_container,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_PURGE_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_flags32,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_action_has_container,
	meta2_filter_action_purge_container,
	NULL
};

static gridd_filter M2V2_DEDUP_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_flags32,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_has_container,
	meta2_filter_action_deduplicate_container,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_LIST_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_flags32,
	meta2_filter_extract_list_params,
	meta2_filter_extract_header_localflag,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_has_container,
	meta2_filter_action_list_contents,
	NULL
};

static gridd_filter M2V2_BEANS_FILTER[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_append,
	meta2_filter_extract_header_mdsys,
	meta2_filter_extract_header_spare,
	meta2_filter_extract_header_storage_policy,
	meta2_filter_extract_header_string_size,
	meta2_filter_extract_header_localflag,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_extract_body_beans,
	meta2_filter_action_has_container,
	meta2_filter_action_generate_beans,
	NULL
};

static gridd_filter M2V2_PUT_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_copy,
	meta2_filter_extract_header_optional_overwrite,
	meta2_filter_extract_header_localflag,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_extract_body_beans,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_is_writable,
	meta2_filter_action_has_container,
	meta2_filter_action_put_content,
	meta2_filter_action_notify_content_PUT,
	NULL
};

static gridd_filter M2V2_APPEND_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_extract_body_beans,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_is_writable,
	meta2_filter_extract_header_storage_policy,
	meta2_filter_action_has_container,
	meta2_filter_action_append_content,
	meta2_filter_action_notify_content_PUT,
	NULL
};

static gridd_filter M2V2_GET_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_optional_chunkid,
	meta2_filter_extract_header_optional_max_keys,
	meta2_filter_extract_header_localflag,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_extract_header_flags32,
	meta2_filter_action_has_container,
	meta2_filter_action_get_content,
	NULL
};

static gridd_filter M2V2_DELETE_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_localflag,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_extract_header_flags32,
	meta2_filter_action_has_container,
	meta2_filter_action_delete_content,
	//meta2_filter_action_notify_content_DELETE,
	NULL
};

static gridd_filter M2V2_PROPSET_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_prop_action,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_extract_header_flags32,
	meta2_filter_extract_body_beans,
	meta2_filter_check_ns_is_master,
	meta2_filter_action_has_container,
	meta2_filter_action_set_content_properties,
	NULL
};

static gridd_filter M2V2_PROPGET_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_extract_header_flags32,
	meta2_filter_action_has_container,
	meta2_filter_action_get_content_properties,
	NULL
};

static gridd_filter M2V2_STGPOL_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_storage_policy,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_has_container,
	meta2_filter_action_update_storage_policy,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_SNAPTAKE_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_snapshot_name,
	meta2_filter_action_has_container,
	meta2_filter_action_take_snapshot,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_SNAPLIST_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_has_container,
	meta2_filter_action_list_snapshots,
	NULL
};

static gridd_filter M2V2_SNAPRESTORE_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_extract_header_snapshot_hardrestore,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_snapshot_name,
	meta2_filter_action_has_container,
	meta2_filter_action_restore_snapshot,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_SNAPDEL_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_snapshot_name,
	meta2_filter_action_has_container,
	meta2_filter_action_delete_snapshot,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_EXITELECTION_FILTERS[] =
{
	meta2_filter_extract_header_ns,
	meta2_filter_extract_header_optional_cid,
	meta2_filter_action_exit_election,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_RAW_DEL[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_extract_body_beans,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_has_container,
	meta2_filter_action_delete_beans,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_SUBST_CHUNKS_FILTERS[] =
{
	meta2_filter_extract_header_url,
	meta2_filter_fill_subject,
	meta2_filter_extract_header_chunk_beans,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_has_container,
	meta2_filter_action_substitute_chunks,
	meta2_filter_success_reply,
	NULL
};

/* ------------------------------------------------------------------------- */

static gridd_filter M2V2_FILTERS_create_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cname,
	meta2_filter_extract_header_cid,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_is_writable,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_extract_header_storage_policy,
	meta2_filter_action_create_container_v1,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_destroy_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_extract_header_forceflag,
	meta2_filter_extract_header_purgeflag,
	meta2_filter_extract_header_flushflag,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_has_container,
	meta2_filter_action_delete_container,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_open_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_is_writable,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_has_container,
	meta2_filter_action_open_container,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_close_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_is_writable,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_has_container,
	meta2_filter_action_close_container,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_add_v1[] =
{
	meta2_filter_extract_header_cid,
	meta2_filter_extract_header_path,
	meta2_filter_pack_url,
	meta2_filter_fill_subject,
	meta2_filter_extract_header_string_size,
	meta2_filter_extract_header_mdsys,
	meta2_filter_extract_header_mdusr,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_has_container,
	meta2_filter_action_generate_chunks,
	NULL
};

static gridd_filter M2V2_FILTERS_append_v1[] =
{
	meta2_filter_extract_header_cid,
	meta2_filter_extract_header_path,
	meta2_filter_pack_url,
	meta2_filter_fill_subject,
	meta2_filter_extract_header_string_size,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_has_container,
	meta2_filter_action_generate_append_chunks,
	NULL
};

static gridd_filter M2V2_FILTERS_spare_v1[] =
{
	meta2_filter_extract_header_cid,
	meta2_filter_extract_header_path,
	meta2_filter_extract_header_storage_policy,
	meta2_filter_pack_url,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_action_has_container,
	meta2_filter_action_get_spare_chunks,
	NULL
};

static gridd_filter M2V2_FILTERS_chunk_commit_v1[] =
{
	meta2_filter_extract_header_cid,
	meta2_filter_extract_header_path,
	meta2_filter_pack_url,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_extract_body_chunk_info,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_is_writable,
	meta2_filter_action_has_container,
	meta2_filter_action_update_chunk_md5,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_content_commit_v1[] =
{
	meta2_filter_extract_header_cid,
	meta2_filter_extract_header_path,
	meta2_filter_pack_url,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_is_writable,
	meta2_filter_action_has_container,
	meta2_filter_action_content_commit_v1,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_content_rollback_v1[] =
{
	meta2_filter_extract_header_cid,
	meta2_filter_extract_header_path,
	meta2_filter_pack_url,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_check_ns_name,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_is_writable,
	meta2_filter_action_has_container,
	meta2_filter_action_content_rollback_v1,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_list_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_extract_list_params,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_list_v1,
	NULL
};

static gridd_filter M2V2_FILTERS_set_content_prop_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_header_path_f1,
	meta2_filter_extract_header_propname_f2,
	meta2_filter_extract_header_propvalue_f3,
	meta2_filter_action_has_container,
	meta2_filter_action_set_content_prop_v1,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_get_content_prop_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_header_path_f1,
	meta2_filter_extract_header_propname_f2,
	meta2_filter_action_has_container,
	meta2_filter_action_get_content_prop_v1,
	NULL
};

static gridd_filter M2V2_FILTERS_list_all_content_properties[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_header_path_f1,
	meta2_filter_action_has_container,
	meta2_filter_action_list_all_content_properties,
	NULL
};

static gridd_filter M2V2_FILTERS_remove_content_prop_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_header_path_f1,
	meta2_filter_extract_header_propname_f2,
	meta2_filter_action_has_container,
	meta2_filter_action_remove_content_prop_v1,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_modify_mdusr_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_extract_header_path_f1,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_opt_header_string_V_f2,
	meta2_filter_action_has_container,
	meta2_filter_action_modify_mdusr_v1,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_modify_mdsys_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_extract_header_path_f1,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_header_string_V_f2,
	meta2_filter_action_has_container,
	meta2_filter_action_modify_mdsys_v1,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_set_container_prop_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_header_string_K_f1,
	meta2_filter_extract_header_string_V_f2,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_is_writable,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_check_prop_key_prefix,
	meta2_filter_action_has_container,
	meta2_filter_action_set_container_properties,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_replicate_container_properties[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_header_string_K_f1,
	meta2_filter_extract_header_string_V_f2,
	meta2_filter_check_ns_is_slave,
	meta2_filter_check_ns_is_writable,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_has_container,
	meta2_filter_action_set_container_properties,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_get_container_prop_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_header_string_K_f1,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_is_writable,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_has_container,
	meta2_filter_action_get_container_prop_v1,
	NULL
};

static gridd_filter M2V2_FILTERS_list_usr_container_properties[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_list_usr_container_properties,
	NULL
};

static gridd_filter M2V2_FILTERS_list_all_container_properties[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_list_all_container_properties,
	NULL
};

static gridd_filter M2V2_FILTERS_remove_container_property[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_header_string_K_f1,
	meta2_filter_check_ns_is_master,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_has_container,
	meta2_filter_action_remove_container_properties,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_replicate_remove_container_property[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_extract_header_string_K_f1,
	meta2_filter_check_ns_is_slave,
	meta2_filter_check_ns_not_wormed,
	meta2_filter_action_has_container,
	meta2_filter_action_remove_container_properties,
	/* TODO Post an event */
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_getflags[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_get_flags,
	NULL
};

static gridd_filter M2V2_FILTERS_setflags[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_extract_body_flags32,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_set_flags,
	NULL
};


static gridd_filter M2V2_FILTERS_enable[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_enable,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_disable[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_disable,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_freeze[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_freeze,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_disable_frozen[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_disable_frozen,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_restore_container[] =
{
	meta2_filter_extract_header_cid_dst,
	meta2_filter_extract_header_cid_src,
	meta2_filter_extract_header_addr_src,
	meta2_filter_pack_url,
	meta2_filter_fill_subject,
	meta2_filter_check_backend,
	meta2_filter_action_restore_container,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_add_service_content[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_extract_header_srvtype_f1,
	meta2_filter_fill_subject,
	meta2_filter_extract_body_strlist,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_add_service_content,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_spare_service_content[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_extract_header_srvtype_f1,
	meta2_filter_fill_subject,
	meta2_filter_extract_body_strlist,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_add_service_content,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_flush_content_services[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_extract_header_srvtype_f1,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_flush_content_services,
	NULL
};

static gridd_filter M2V2_FILTERS_delete_content_services[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_extract_header_srvtype_f1,
	meta2_filter_fill_subject,
	meta2_filter_extract_body_strlist,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_del_content_services,
	NULL
};

static gridd_filter M2V2_FILTERS_commit_service_content[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_extract_header_srvtype_f1,
	meta2_filter_fill_subject,
	meta2_filter_extract_body_strlist,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_rollback_service_content[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_extract_header_srvtype_f1,
	meta2_filter_fill_subject,
	meta2_filter_extract_body_strlist,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_list_content_services[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_extract_header_srvtype_f1,
	meta2_filter_extract_header_path_f2,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_list_content_services,
	NULL
};

static gridd_filter M2V2_FILTERS_list_all_content_services[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_extract_header_srvtype_f1,
	meta2_filter_extract_header_path_f2,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_list_all_content_services,
	NULL
};

static gridd_filter M2V2_FILTERS_retrieve_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_extract_header_path,
	meta2_filter_pack_url,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_retrieve_v1,
	NULL
};

static gridd_filter M2V2_FILTERS_raw_list_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_pack_url,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_raw_list_v1,
	NULL
};

static gridd_filter M2V2_FILTERS_raw_chunks_get_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_extract_header_path,
	meta2_filter_pack_url,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_raw_chunks_get_v1,
	NULL
};

static gridd_filter M2V2_FILTERS_remove_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_extract_header_path,
	meta2_filter_pack_url,
	meta2_filter_fill_subject,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_remove_v1,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_del_raw_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_body_rawcontentv1,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_remove_raw_v1,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_set_raw_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_optional_position_prefix,
	meta2_filter_extract_body_rawcontentv1,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_add_raw_v1,
	meta2_filter_success_reply,
	NULL
};

static gridd_filter M2V2_FILTERS_getall_admin_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_getall_admin_v1,
	NULL
};

static gridd_filter M2V2_FILTERS_setone_admin_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_setone_admin_v1,
	NULL
};

static gridd_filter M2V2_FILTERS_touch_content_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
	meta2_filter_extract_header_path,
	meta2_filter_pack_url,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_touch_content_v1,
	NULL
};

static gridd_filter M2V2_FILTERS_touch_container_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid,
    meta2_filter_extract_header_flags32,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_touch_container_v1,
	NULL
};

static gridd_filter M2V2_FILTERS_replicatev2_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_body_rawcontentv2,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_replicate_content_v1,
	NULL
};

static gridd_filter M2V2_FILTERS_statv2_v1[] =
{
	meta2_filter_extract_header_optional_ns,
	meta2_filter_extract_header_cid_f0,
	meta2_filter_extract_header_path_f1,
	meta2_filter_check_optional_ns_name,
	meta2_filter_check_backend,
	meta2_filter_action_has_container,
	meta2_filter_action_statv2_v1,
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
		{"M2V2_CREATE",    (hook) meta2_dispatch_all, M2V2_CREATE_FILTERS},
		{"M2V2_DESTROY",   (hook) meta2_dispatch_all, M2V2_DESTROY_FILTERS},
		{"M2V2_HAS",	   (hook) meta2_dispatch_all, M2V2_HAS_FILTERS},
		{"M2V2_PURGE",     (hook) meta2_dispatch_all, M2V2_PURGE_FILTERS},
		{"M2V2_DEDUP",     (hook) meta2_dispatch_all, M2V2_DEDUP_FILTERS},
		/* contents */
		{"M2V2_BEANS",     (hook) meta2_dispatch_all, M2V2_BEANS_FILTER},
		{"M2V2_PUT",       (hook) meta2_dispatch_all, M2V2_PUT_FILTERS},
		{"M2V2_APPEND",    (hook) meta2_dispatch_all, M2V2_APPEND_FILTERS},
		{"M2V2_GET",       (hook) meta2_dispatch_all, M2V2_GET_FILTERS},
		{"M2V2_DEL",       (hook) meta2_dispatch_all, M2V2_DELETE_FILTERS},
		{"M2V2_LIST",      (hook) meta2_dispatch_all, M2V2_LIST_FILTERS},
		/* url */
		{"M2V2_STGPOL",    (hook) meta2_dispatch_all, M2V2_STGPOL_FILTERS},
		/* properties */
		{"M2V2_PROP_SET",  (hook) meta2_dispatch_all, M2V2_PROPSET_FILTERS},
		{"M2V2_PROP_GET",  (hook) meta2_dispatch_all, M2V2_PROPGET_FILTERS},
		/* snapshots */
		{"M2V2_SNAP_TAKE", (hook) meta2_dispatch_all, M2V2_SNAPTAKE_FILTERS},
		{"M2V2_SNAP_LIST", (hook) meta2_dispatch_all, M2V2_SNAPLIST_FILTERS},
		{"M2V2_SNAP_RESTORE", (hook) meta2_dispatch_all, M2V2_SNAPRESTORE_FILTERS},
		{"M2V2_SNAP_DEL",  (hook) meta2_dispatch_all, M2V2_SNAPDEL_FILTERS},

		/* raw beans */
		{"M2V2_RAW_DEL",   (hook) meta2_dispatch_all, M2V2_RAW_DEL},
		{"M2V2_SUBST_CHUNKS",   (hook) meta2_dispatch_all, M2V2_SUBST_CHUNKS_FILTERS},

		{"M2V2_EXITELECTION", (hook) meta2_dispatch_all,  M2V2_EXITELECTION_FILTERS},

		{NULL, NULL, NULL}
	};

	return descriptions;
}

const struct gridd_request_descr_s *
meta2_gridd_get_v1_requests(void)
{
	/* old poly-shot features */
	static struct gridd_request_descr_s descriptions[] = {

		/* CONTAINER */
		{"REQ_M2_CREATE", (hook) meta2_dispatch_all, M2V2_FILTERS_create_v1},
		{"REQ_M2_DESTROY", (hook) meta2_dispatch_all, M2V2_FILTERS_destroy_v1},
		{"REQ_M2_OPEN", (hook) meta2_dispatch_all, M2V2_FILTERS_open_v1},
		{"REQ_M2_CLOSE", (hook) meta2_dispatch_all, M2V2_FILTERS_close_v1},
		{"REQ_M2_LIST", (hook) meta2_dispatch_all, M2V2_FILTERS_list_v1},
		{"META2_SERVICES_LIST_CONTENT_SPECIF", (hook) meta2_dispatch_all, M2V2_FILTERS_list_v1},

		/* CONTAINER PROPERTIES */
		{"REQ_M2RAW_ADMIN_GETALL", (hook) meta2_dispatch_all, M2V2_FILTERS_getall_admin_v1},
		{"REQ_M2RAW_ADMIN_SETONE", (hook) meta2_dispatch_all, M2V2_FILTERS_setone_admin_v1},
		{"META2_SERVICES_SET_CONTAINER_GLOBAL_PROPERTY", (hook) meta2_dispatch_all, M2V2_FILTERS_set_container_prop_v1},
		{"META2_SERVICES_SET_CONTAINER_PROPERTY", (hook) meta2_dispatch_all, M2V2_FILTERS_set_container_prop_v1},
		{"META2_SERVICES_REPLICATE_SET_CONTAINER_PROPERTY", (hook) meta2_dispatch_all, M2V2_FILTERS_replicate_container_properties},
		{"META2_SERVICES_GET_CONTAINER_PROPERTY", (hook) meta2_dispatch_all, M2V2_FILTERS_get_container_prop_v1},
		{"META2_SERVICES_LIST_ALL_CONTAINER_PROPERTIES", (hook) meta2_dispatch_all, M2V2_FILTERS_list_all_container_properties},
		{"META2_SERVICES_LIST_CONTAINER_PROPERTIES", (hook) meta2_dispatch_all, M2V2_FILTERS_list_usr_container_properties},
		{"META2_SERVICES_REMOVE_CONTAINER_PROPERTY", (hook) meta2_dispatch_all, M2V2_FILTERS_remove_container_property},
		{"META2_SERVICES_REPLICATE_REMOVE_CONTAINER_PROPERTY", (hook) meta2_dispatch_all, M2V2_FILTERS_replicate_remove_container_property},

		/* CONTENT LEVEL */
		{"REQ_M2_CONTENTADD", (hook) meta2_dispatch_all, M2V2_FILTERS_add_v1},
		{"REQ_M2_CHUNK_COMMIT", (hook) meta2_dispatch_all, M2V2_FILTERS_chunk_commit_v1},
		{"REQ_M2_CONTENTRETRIEVE", (hook) meta2_dispatch_all, M2V2_FILTERS_retrieve_v1},
		{"REQ_M2_CONTENTREMOVE", (hook) meta2_dispatch_all, M2V2_FILTERS_remove_v1},
		{"REQ_M2_CONTENTCOMMIT", (hook) meta2_dispatch_all, M2V2_FILTERS_content_commit_v1},
		{"REQ_M2_CONTENTSPARE", (hook) meta2_dispatch_all, M2V2_FILTERS_spare_v1},
		{"REQ_M2_CONTENTAPPEND", (hook) meta2_dispatch_all, M2V2_FILTERS_append_v1},
		{"REQ_M2_CONTENTROLLBACK", (hook) meta2_dispatch_all, M2V2_FILTERS_content_rollback_v1},
		{"META2_SERVICES_STAT_CONTENT_V2", (hook) meta2_dispatch_all, M2V2_FILTERS_statv2_v1},

		{"REQ_M2RAW_CONTENT_GET", (hook) meta2_dispatch_all, M2V2_FILTERS_raw_chunks_get_v1},
		{"REQ_M2RAW_CHUNKS_GET", (hook) meta2_dispatch_all, M2V2_FILTERS_raw_chunks_get_v1},
		{"REQ_M2RAW_CONTENT_GETBYPATH", (hook) meta2_dispatch_all, M2V2_FILTERS_raw_chunks_get_v1},
		{"REQ_M2RAW_CONTENT_GETALL", (hook) meta2_dispatch_all, M2V2_FILTERS_raw_list_v1},

		{"REQ_M2RAW_CONTENT_DEL", (hook) meta2_dispatch_all, M2V2_FILTERS_del_raw_v1},
		{"REQ_M2RAW_CHUNKS_DEL", (hook) meta2_dispatch_all, M2V2_FILTERS_del_raw_v1},

		// Necessary to the rawx-mover
		{"REQ_M2RAW_CONTENT_SET", (hook) meta2_dispatch_all, M2V2_FILTERS_set_raw_v1},
		{"REQ_M2RAW_CHUNKS_SET", (hook) meta2_dispatch_all, M2V2_FILTERS_set_raw_v1},

		/* CONTENT_PROPERTIES */
		{"META2_SERVICES_SET_CONTENT_PROPERTY", (hook) meta2_dispatch_all, M2V2_FILTERS_set_content_prop_v1},
		{"META2_SERVICES_GET_CONTENT_PROPERTY", (hook) meta2_dispatch_all, M2V2_FILTERS_get_content_prop_v1},
		{"META2_SERVICES_LIST_ALL_CONTENT_PROPERTIES", (hook) meta2_dispatch_all, M2V2_FILTERS_list_all_content_properties},
		{"META2_SERVICES_REMOVE_CONTENT_PROPERTY", (hook) meta2_dispatch_all, M2V2_FILTERS_remove_content_prop_v1},

		/* CONTENT METADATA */
		{"META2_SERVICES_MODIFY_METADATAUSR", (hook) meta2_dispatch_all, M2V2_FILTERS_modify_mdusr_v1},
		{"META2_SERVICES_MODIFY_METADATASYS", (hook) meta2_dispatch_all, M2V2_FILTERS_modify_mdsys_v1},

		/* AGENT EVENTS */
		{"REQ_M2RAW_TOUCH_CONTAINER", (hook) meta2_dispatch_all, M2V2_FILTERS_touch_container_v1},
		{"REQ_M2RAW_TOUCH_CONTENT", (hook) meta2_dispatch_all, M2V2_FILTERS_touch_content_v1},

		/* CONTAINER FLAGS */
		{"REQ_M2_GETFLAG", (hook) meta2_dispatch_all, M2V2_FILTERS_getflags},
		{"REQ_M2_SETFLAG", (hook) meta2_dispatch_all, M2V2_FILTERS_setflags},
		{"META2_SERVICES_CONTAINER_ENABLE", (hook) meta2_dispatch_all, M2V2_FILTERS_enable},
		{"META2_SERVICES_CONTAINER_DISABLE", (hook) meta2_dispatch_all, M2V2_FILTERS_disable},
		{"META2_SERVICES_CONTAINER_FREEZE", (hook) meta2_dispatch_all, M2V2_FILTERS_freeze},
		{"META2_SERVICES_CONTAINER_DISABLE_DISABLED", (hook) meta2_dispatch_all, M2V2_FILTERS_disable_frozen},

		/* RESTORE */
		{"META2_SERVICES_REPLICATE_CONTENT_V2", (hook) meta2_dispatch_all, M2V2_FILTERS_replicatev2_v1},

		{"REQ_M2RAW_RESTORE_CONTAINER", (hook) meta2_dispatch_all, M2V2_FILTERS_restore_container},

		/* CONTENT SERVICES */
		{"META2_SERVICES_SERVICE_ADD_CONTENTS", (hook) meta2_dispatch_all, M2V2_FILTERS_add_service_content},
		{"META2_SERVICES_SERVICE_ADD_SPARES", (hook) meta2_dispatch_all, M2V2_FILTERS_spare_service_content},
		{"META2_SERVICES_SERVICE_COMMIT_CONTENTS", (hook) meta2_dispatch_all, M2V2_FILTERS_commit_service_content},
		{"META2_SERVICES_SERVICE_ROLLBACK_CONTENTS", (hook) meta2_dispatch_all, M2V2_FILTERS_rollback_service_content},

		{"META2_SERVICES_SERVICE_GET_CONTENT_SERVICE", (hook) meta2_dispatch_all, M2V2_FILTERS_list_content_services},
		{"META2_SERVICES_SERVICE_GET_ALL_USED", (hook) meta2_dispatch_all, M2V2_FILTERS_list_all_content_services},

		{"META2_SERVICES_SERVICE_DELETE_CONTENTS", (hook) meta2_dispatch_all, M2V2_FILTERS_delete_content_services},
		{"META2_SERVICES_SERVICE_FLUSH", (hook) meta2_dispatch_all, M2V2_FILTERS_flush_content_services},


		/* Given up */
		{"REQ_M2RAW_CONTENT_GETBYCHUNK", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_CONTAINER_SERVICES_GET_ALL_USED", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_CONTAINER_SERVICES_GET_AVAILABLE", (hook) meta2_dispatch_all, NULL},

		{"REQ_M2_INFO", (hook) meta2_dispatch_all, NULL},
		{"REQ_M2RAW_MARK_REPAIRED", (hook) meta2_dispatch_all, NULL},
		{"REQ_M2RAW_DUMP_CONTAINER", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_ADD_CONTAINER_EVENT", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_REPLICATE_ADD_CONTAINER_EVENT", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_GET_CONTAINER_EVENT_ROWID", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_GET_CONTAINER_EVENTS_BY_TIMESTAMP", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_LIST_CONTAINER_EVENTS", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_LIST_CONTAINER_EVENTS_SINCE", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_LIST_CONTAINER_EVENTS_UP_TO", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_LIST_LAST_CONTAINER_EVENTS", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_LIST_ALL_CONTAINER_EVENTS", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_REMOVE_CONTAINER_EVENT_BY_ROWID", (hook) meta2_dispatch_all, NULL},
		{"META2_SERVICES_REMOVE_CONTAINER_EVENT_BY_EVENT", (hook) meta2_dispatch_all, NULL},

		{NULL, NULL, NULL}
	};

	return descriptions;
}

