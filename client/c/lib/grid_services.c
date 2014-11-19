#include "./gs_internals.h"
#include <meta2/remote/meta2_services_remote.h>

// TODO factorizes with GLib macros
#define GSERR_EINVAL(err) do { if (err) { *err = gs_error_new(EINVAL, "<%s> Invalid parameter", __FUNCTION__); } } while (0)

static void
_update_master(gs_container_t *c, char *master)
{
	if(!master)
		return;

	gs_update_meta1_master(c->info.gs, C0_ID(c), master);

	g_free(master);
}

static addr_info_t*
_unpack_service(gchar *service)
{
	gchar **t = NULL;
	gchar **addr_tok = NULL;
	GError *local_error = NULL;
	addr_info_t* addr = NULL;

	t = g_strsplit(service, "|", 3);
	if(g_strv_length(t) != 3) {
		goto end_label;
	}

	addr_tok = g_strsplit(t[2], ":", 2);
	if(g_strv_length(addr_tok) != 2) {
		goto end_label;
	}

	addr = build_addr_info(addr_tok[0], atoi(addr_tok[1]), &local_error);

end_label:

	if(local_error)
		g_clear_error(&local_error);
	if(addr_tok)
		g_strfreev(addr_tok);
	if(t)
		g_strfreev(t);
	return addr;
}

static void
merge_cnx_in_container(struct metacnx_ctx_s *ctx, gs_container_t *container)
{
	if (container->meta2_cnx != ctx->fd)
		container->meta2_cnx = ctx->fd;
}

static void
init_cnx_with_container(struct metacnx_ctx_s *ctx, gs_container_t *container)
{
	ctx->fd = container->meta2_cnx;
	ctx->timeout.req = container->info.gs->timeout.m2.op;
	ctx->timeout.cnx = container->info.gs->timeout.m2.cnx;
	ctx->flags = METACNX_FLAGMASK_KEEPALIVE;
	ctx->id = NULL;
	memcpy(&(ctx->addr), &(container->meta2_addr), sizeof(addr_info_t));
}

static char**
strdupv(char **argv)
{
	char **result, **arg;
	
	if (!argv)
		return NULL;
	result = calloc(1+g_strv_length(argv), sizeof(char*));
	for (arg=argv; *arg ;arg++) 
		result[ argv-arg ] = strdup(*arg);
	return result;
}

static GSList*
strv_make_hollow_list(char **argv)
{
	GSList *l;
	char **arg;

	l = NULL;
	for (arg=argv; *arg ;arg++)
		l = g_slist_prepend(l,*arg);
	return g_slist_reverse(l);
}

static struct service_info_s*
_make_srvinfo(const gchar *ns, const gchar *srv, const addr_info_t *ai)
{
	struct service_info_s *result;

	result = g_try_malloc0(sizeof(struct service_info_s));
	if (!result) {
		FATAL("Memory allocation failure");
		abort();
		return NULL;
	}

	g_strlcpy(result->ns_name, ns, sizeof(result->ns_name));
	g_strlcpy(result->type, srv, sizeof(result->type));
	memcpy(&(result->addr), ai, sizeof(addr_info_t));
	result->score.value = -1;
	
	return result;
}

static gs_service_t*
_make_service_from_srvinfo(gs_container_t *container, struct service_info_s *si)
{
	gs_service_t *gss;

	gss = g_try_malloc0(sizeof(gs_service_t));
	if (!gss) {
		FATAL("Memory allocation failure");
		abort();
		return NULL;
	}

	gss->gss_container = container;
	gss->gss_si = si;
	return gss;

}

static gs_service_t*
_make_service_from_addr(gs_container_t *container, const gchar *service, const addr_info_t *ai)
{
	return _make_service_from_srvinfo(container,
			_make_srvinfo(gs_get_namespace(container->info.gs), service, ai));
}

static gs_service_t **
_make_service_array_from_services(gs_container_t *container, const char *srvtype, GSList *list_of_srvinfo)
{
	gs_service_t **result;
	GSList *l;
	GPtrArray *pa;

	(void) srvtype;

	pa = g_ptr_array_new();
	for (l=list_of_srvinfo; l ;l=l->next) {
		gs_service_t *gss;

		if (!l->data)
			continue;
		gss = _make_service_from_srvinfo(container, l->data);
		if (gss)
			g_ptr_array_add(pa, gss);
	}
	g_ptr_array_add(pa,NULL);
	result = (gs_service_t**) pa->pdata;
	g_ptr_array_free(pa, FALSE);

	return result;
}

static gs_service_t **
_make_service_array_from_addresses(gs_container_t *container, const char *srvtype, GSList *list_addr)
{
	gs_service_t **result;
	GSList *l;
	GPtrArray *pa;

	pa = g_ptr_array_new();
	for (l=list_addr; l ;l=l->next) {
		gs_service_t *gss;

		if (!l->data)
			continue;
		gss = _make_service_from_addr(container, srvtype, l->data);
		if (gss)
			g_ptr_array_add(pa, gss);
	}
	g_ptr_array_add(pa,NULL);
	result = (gs_service_t**) pa->pdata;
	g_ptr_array_free(pa, FALSE);

	return result;
}


static gs_service_t**
addrlist_make_service_array(GSList *argl, const char *srvtype, gs_container_t *container)
{
	unsigned int i;
	GSList *l;
	gs_service_t **result;

	result = calloc(1+g_slist_length(argl),sizeof(gs_service_t*));
	if (!result)
		abort();
	for (i=0,l=argl; l ;l=l->next) {
		if (!l->data)
			continue;
		result[i++] = _make_service_from_addr(container, srvtype, l->data);
	}
	return result;
}

static char**
strlist_make_deep_copy(GSList *argl)
{
	unsigned int i;
	GSList *l;
	char **result;

	result = calloc(1+g_slist_length(argl),sizeof(char*));
	if (!result)
		abort();
	for (i=0,l=argl; l ;l=l->next) {
		if (!l->data)
			continue;
		result[i++] = strdup(l->data);
	}
	return result;
}

/* ------------------------------------------------------------------------- */

size_t
gs_service_get_url(const gs_service_t * service, char *dst, size_t dst_size)
{
	if (!service || !dst || !dst_size)
		return 0;
	return addr_info_to_string(&(service->gss_si->addr), dst, dst_size);
}

socklen_t
gs_service_get_address(const gs_service_t *service, struct sockaddr *sa, socklen_t sa_size)
{
	gsize result_gsize;
	gint rc;

	if (!service || !sa || !sa_size)
		return 0;

	result_gsize = sa_size;
	rc = addrinfo_to_sockaddr(&(service->gss_si->addr), sa, &result_gsize);
	return rc ? result_gsize : 0;
}

void
gs_free_service(gs_service_t * service)
{
	if (!service)
		return;
	if (service->gss_si)
		service_info_clean(service->gss_si);
	memset(service, 0x00, sizeof(struct gs_service_s));
	g_free(service);
}

const char *
gs_service_get_type(const gs_service_t * service)
{
	if (!service)
		return "";
	if (!service->gss_si)
		return "";
	return service->gss_si->type;
}

void
gs_service_free_array( gs_service_t **services )
{
	gs_service_t **srv_cursor;
	if (!services)
		return;
	for (srv_cursor=services; *srv_cursor ;srv_cursor++)
		gs_free_service( *srv_cursor);
	g_free(services);
}

/* ------------------------------------------------------------------------- */

gs_service_t **
gs_get_services_for_paths(gs_container_t * container, const char *srvtype,
	char **paths, gs_error_t ** err)
{
	char **path;
	struct metacnx_ctx_s ctx;
	addr_info_t *ai;
	void **result;
	GPtrArray *pa;

	if (!container || !paths) {
		GSERR_EINVAL(err);
		return NULL;
	}

	init_cnx_with_container(&ctx,container);
	pa = g_ptr_array_new();
	
	for (path=paths; *path ;path++) {
		gs_service_t *gss;
		GError *gerr;
		
		gerr = NULL;
		ai = meta2_remote_service_get_content_service(&ctx, C0_ID(container), srvtype, *path, &gerr );
		if (!ai)
			metacnx_close(&ctx);
		merge_cnx_in_container(&ctx,container);
		if (!ai) {
			GSERRORCAUSE(err,gerr,"Failed to get the content for [%s]", *path);
			if (gerr)
				g_error_free(gerr);
			g_ptr_array_free(pa,TRUE);
			return NULL;
		}
		if (gerr)
			g_error_free(gerr);

		gss = _make_service_from_addr(container, srvtype, ai);
		if (gss)
			g_ptr_array_add(pa, gss);
		g_free(ai);
	}

	g_ptr_array_add(pa,NULL);
	result = pa->pdata;
	g_ptr_array_free(pa,FALSE);

	return (gs_service_t**) result;
}

gs_service_t *
gs_choose_service_for_paths(gs_container_t * container, const char *srvtype,
	char **paths, gs_error_t ** err)
{
	char **path;
	GSList *paths_list;
	GError *gerr;
	struct service_info_s *si;
	struct metacnx_ctx_s ctx;
	
	if (!container || !paths || !*paths) {
		GSERR_EINVAL(err);
		return NULL;
	}

	/*make the request on a path list, then free the list*/
	paths_list = NULL;
	for (path=paths; *path ;path++)
		paths_list = g_slist_prepend(paths_list,*path);
	gerr = NULL;
	
	init_cnx_with_container(&ctx,container);
	si = meta2_remote_service_add_contents(&ctx, C0_ID(container), srvtype, paths_list, &gerr);
	if (!si)
		metacnx_close(&ctx);
	merge_cnx_in_container(&ctx,container);

	g_slist_free(paths_list);
	
	if (!si) {
		GSERRORCAUSE(err,gerr,"Failed to add at least one of the paths");
		if (gerr)
			g_error_free(gerr);
		return NULL;
	}

	/*Wrap the service_info_s in gs_service_t*/
	return _make_service_from_srvinfo(container, si);
}

gs_status_t
gs_delete_services_for_paths(gs_container_t * container, const char *srvtype,
	char **paths, char ***really_removed, gs_service_t ***services_used, gs_error_t ** err)
{
	status_t rc;
	char **path;
	struct metacnx_ctx_s ctx;
	GError *gerr;
	GSList *removed, *to_be_removed, *used;
	
	if (!container || !paths) {
		GSERR_EINVAL(err);
		if (really_removed)
			*really_removed = NULL;
		return GS_ERROR;
	}

	gerr = NULL;
	removed = to_be_removed = used = NULL;

	for (path=paths; *path ;path++)
		to_be_removed = g_slist_prepend(to_be_removed,*path);
		
	init_cnx_with_container(&ctx,container);
	rc = meta2_remote_service_delete_contents(&ctx, C0_ID(container), srvtype,
		to_be_removed, &removed, &used, &gerr);
	if (!rc)
		metacnx_close(&ctx);
	merge_cnx_in_container(&ctx,container);

	g_slist_free(to_be_removed);

	if (!rc) {
		GSERRORCAUSE(err,gerr,"Failed to remove (at least one of) the pahs");
		if (really_removed)
			*really_removed = NULL;
		if (services_used)
			*services_used = NULL;
	}
	else {
		if (really_removed)
			*really_removed = strlist_make_deep_copy(removed);
		if (services_used)
			*services_used = addrlist_make_service_array(used, srvtype, container);
	}

	if (gerr)
		g_error_free(gerr);
	if (removed) {
		g_slist_foreach(removed,g_free1,NULL);
		g_slist_free(removed);
	}
	if (used) {
		g_slist_foreach(used,g_free1,NULL);
		g_slist_free(used);
	}
	return rc ? GS_OK : GS_ERROR;
}

char**
gs_validate_changes_on_paths(gs_container_t *container, const char *srvtype,
	char **paths, gs_error_t ** err)
{
	char **result;
	status_t rc;
	GError *gerr;
	GSList *failed_list, *to_be_validated;
	struct metacnx_ctx_s ctx;
	
	if (!container) {
		GSERR_EINVAL(err);
		return strdupv(paths);
	}
	if (!paths) {
		GSERR_EINVAL(err);
		return NULL;
	}
	
	rc = ~0;
	gerr = NULL;
	failed_list = NULL;
	to_be_validated = strv_make_hollow_list(paths);

	init_cnx_with_container(&ctx,container);
	if (to_be_validated) {
		GSList *list_of_lists, *l;

		list_of_lists = gslist_split(to_be_validated, 50);
		for (l=list_of_lists; l ;l=l->next) {
			GSList *failed_now = NULL;
			rc &= meta2_remote_service_commit_contents(&ctx, C0_ID(container),
				srvtype, l->data, &failed_now, &gerr);
			merge_cnx_in_container(&ctx,container);
			failed_list = g_slist_concat(failed_list, failed_now);
		}
		gslist_chunks_destroy(list_of_lists, NULL);
	}
	merge_cnx_in_container(&ctx,container);

	g_slist_free(to_be_validated);

	result = NULL;
	if (!rc) {
		GSERRORCAUSE(err,gerr,"Failed to validate some changes");	
		result = strlist_make_deep_copy(failed_list);
		g_slist_foreach(failed_list,g_free1,NULL);
		g_slist_free(failed_list);
	}

	if (gerr)
		g_error_free(gerr);
	return result;
}

char**
gs_invalidate_changes_on_paths(gs_container_t *container, const char *srvtype,
	char **paths, gs_error_t ** err)
{
	char **result;
	status_t rc;
	GError *gerr;
	GSList *failed_list, *to_be_validated;
	struct metacnx_ctx_s ctx;
	
	if (!container) {
		GSERR_EINVAL(err);
		return strdupv(paths);
	}
	if (!paths) {
		GSERR_EINVAL(err);
		return NULL;
	}
	
	rc = ~0;
	gerr = NULL;
	failed_list = NULL;
	to_be_validated = strv_make_hollow_list(paths);

	init_cnx_with_container(&ctx,container);
	if (to_be_validated) {
		GSList *list_of_lists, *l;

		list_of_lists = gslist_split(to_be_validated, 50);
		for (l=list_of_lists; l ;l=l->next) {
			GSList *failed_now = NULL;
			rc &= meta2_remote_service_rollback_contents(&ctx, C0_ID(container),
				srvtype, l->data, &failed_now, &gerr);
			merge_cnx_in_container(&ctx,container);
			failed_list = g_slist_concat(failed_list, failed_now);
		}
		gslist_chunks_destroy(list_of_lists, NULL);
	}
	if (!rc)
		metacnx_close(&ctx);
	merge_cnx_in_container(&ctx,container);

	g_slist_free(to_be_validated);

	result = NULL;
	if (!rc) {
		GSERRORCAUSE(err,gerr,"Failed to validate some changes");	
		result = strlist_make_deep_copy(failed_list);
		g_slist_foreach(failed_list,g_free1,NULL);
		g_slist_free(failed_list);
	}

	if (gerr)
		g_error_free(gerr);
	return result;
}


gs_service_t**
gs_get_all_services_used( gs_container_t *container, const gchar *srvtype, gs_error_t **err)
{
	gs_service_t **result;
	GError *gerr = NULL;
	GSList *list_addr = NULL;
	
	if (!container) {
		GSERR_EINVAL(err);
		return NULL;
	}

        addr_info_t *meta1_addr = NULL;
	gchar **tmp = NULL;

        meta1_addr = gs_resolve_meta1 (container->info.gs, C0_ID(container), &gerr);
	tmp = meta1v2_remote_list_reference_services(meta1_addr, &gerr,
			gs_get_full_vns(container->info.gs), C0_ID(container), srvtype,
			C0_M1CNX(container)/1000, C0_M1TO(container)/1000);
	/* TODO: make a list of addr_info from a list of string services */
	guint i = 0;
	for( i= 0 ; i < g_strv_length(tmp); i++) {
		if(!tmp[i] && strlen(tmp[i]) <= 0)
			continue;
		gchar **t = NULL;
		gchar **addr_tok = NULL;
		addr_info_t* addr = NULL;
		t = g_strsplit(tmp[i], "|", 3);
		if(g_strv_length(t) != 3)
			continue;
		addr_tok = g_strsplit(t[2], ":", 2);
		if(g_strv_length(addr_tok) != 2)
			continue;
		if((addr = build_addr_info(addr_tok[0], atoi(addr_tok[1]), &gerr)) != NULL)
			list_addr = g_slist_prepend(list_addr, addr);
		if(addr_tok)
			g_strfreev(addr_tok);
		if(t)
			g_strfreev(t);
	}

	result = _make_service_array_from_addresses(container, srvtype, list_addr);
	
	if (list_addr) {
		g_slist_foreach(list_addr, g_free1, NULL);
		g_slist_free(list_addr);
	}
	if (gerr)
		g_error_free(gerr);

	if(tmp)
		g_strfreev(tmp);

	return result;
}

gs_service_t**
gs_service_flush(gs_container_t *container, const char *srvtype, gs_error_t **err)
{
	gboolean rc;
	gs_service_t **result;
	struct metacnx_ctx_s ctx;
	GError *gerr;
	GSList *list_addr;
	
	if (!container) {
		GSERR_EINVAL(err);
		return 0;
	}

	gerr = NULL;
	list_addr = NULL;

	init_cnx_with_container(&ctx,container);
	rc = meta2_remote_service_flush(&ctx, C0_ID(container), srvtype, &list_addr, &gerr);
	if (rc != GS_OK)
		metacnx_close(&ctx);
	merge_cnx_in_container(&ctx,container);
	
	if (!rc || gerr) {
		GSERRORCAUSE(err,gerr,"Failed to flush the indexes of type [%s] used by [%s]", srvtype, C0_NAME(container));
		result = NULL;
	}
	else {
		result = _make_service_array_from_addresses(container, srvtype, list_addr);
	}
	
	if (list_addr) {
		g_slist_foreach(list_addr, g_free1, NULL);
		g_slist_free(list_addr);
	}
	if (gerr)
		g_error_free(gerr);

	return result;
}

/* ------------------------------------------------------------------------- */

gs_service_t**
gs_container_service_get_all(gs_container_t *container, const char *srvtype, gs_error_t **err)
{
	gs_service_t **result = NULL;
	GError *gerr = NULL;
	GSList *list_of_srvinfo = NULL;
	gchar **srv_str_list = NULL;
	addr_info_t *meta1_addr = NULL;

	if (!container || !srvtype || !*srvtype) {
		GSERRORCODE(err, EINVAL, "Invalid parameter (%p %p)", container, srvtype);
		return NULL;
	}

	GSList *exclude = NULL;

	int nb_try = 0;
	while(nb_try < 3) {
		nb_try++;
		meta1_addr = gs_resolve_meta1v2(container->info.gs, C0_ID(container),
				C0_NAME(container), 1, &exclude, &gerr);

		if(!meta1_addr)	{
			if(gerr) {
				GSERRORCAUSE(err,gerr, "Failed to resolve meta1 for container [%s]",
						C0_NAME(container));
			}
			result = NULL;
			goto end_label;
		}

		srv_str_list = meta1v2_remote_list_reference_services(meta1_addr, &gerr,
				gs_get_full_vns(container->info.gs), C0_ID(container), srvtype,
				C0_M1CNX(container)/1000, C0_M1TO(container)/1000);

		if (!srv_str_list) {
			if(gerr) {
				/* retry if meta1 internal error or network/local error */
				if(gerr->code >= 500 || gerr->code < 100) {
					exclude = g_slist_prepend(exclude, meta1_addr);
					continue;
				} else
					GSERRORCAUSE(err,gerr, "No service of type [%s] found for container [%s]",srvtype, C0_NAME(container));
			}
			result = NULL;
			break;
		} else {
			service_info_t *srv = NULL;
			guint i = 0;
			for(i = 0; i < g_strv_length(srv_str_list); i++) {
				if(!srv_str_list[i] || strlen(srv_str_list[i]) <= 0)
					continue;
				srv = g_malloc0(sizeof(service_info_t));
				g_snprintf(srv->ns_name, sizeof(srv->ns_name), "%s",
						gs_get_namespace(container->info.gs));
				g_snprintf(srv->type, sizeof(srv->type), "%s", srvtype);
				addr_info_t* tmp = NULL;
				tmp = _unpack_service(srv_str_list[i]);
				memcpy(&(srv->addr), tmp, sizeof(addr_info_t));
				if(tmp)
					g_free(tmp);
				list_of_srvinfo = g_slist_prepend(list_of_srvinfo, srv);
			}
			result  = _make_service_array_from_services(container, srvtype, list_of_srvinfo);
			break;
		}
	}

end_label:

	if(exclude) {
		g_slist_foreach(exclude, addr_info_gclean, NULL);
		g_slist_free(exclude);
	}

	if(srv_str_list) {
		g_strfreev(srv_str_list);
	}

	if (list_of_srvinfo) {
		g_slist_free(list_of_srvinfo);
	}
	if (gerr)
		g_error_free(gerr);

	if(meta1_addr)
		g_free(meta1_addr);

	return result;
}

gs_service_t**
gs_container_service_get_available(gs_container_t *container, const char *srvtype, gs_error_t **err)
{
	gs_service_t **result = NULL;
	GError *gerr = NULL;
	GSList *list_of_srvinfo = NULL;
	addr_info_t* meta1_addr = NULL;
	gchar **str_srv = NULL;
	char *master = NULL;

	if (!container || !srvtype || !*srvtype) {
		GSERRORCODE(err, EINVAL, "Invalid parameter (%p %p)", container, srvtype);
		return NULL;
	}
	GSList *exclude = NULL;

	while(1) {
		meta1_addr = gs_resolve_meta1v2(container->info.gs, C0_ID(container),
				C0_NAME(container), 0, &exclude, &gerr);

		if(!meta1_addr) {
			GSERRORCAUSE(err,gerr, "No service of type [%s] found for container [%s]",
					srvtype, C0_NAME(container));
			result = NULL;
			goto end_label;
		}
		str_srv = meta1v2_remote_link_service(meta1_addr, &gerr,
				gs_get_full_vns(container->info.gs), C0_ID(container), srvtype,
				C0_M1CNX(container)/1000.0, C0_M1TO(container)/1000.0, &master);

		_update_master(container, master);

		if (!str_srv) {
			if(gerr) {
				/* retry if meta1 internal error or network / local error */
				if (gerr->code >= 500 || gerr->code < 100) {
					exclude = g_slist_prepend(exclude, meta1_addr);
					continue;
				}
				GSERRORCAUSE(err,gerr, "No service of type [%s] found for container [%s]",
						srvtype, C0_NAME(container));
			}
			result = NULL;
			break;
		} else {
			/* TODO: service_info from str */
			guint i = 0;
			for(i = 0; i < g_strv_length(str_srv); i++) {
				if(!str_srv[i] || strlen(str_srv[i]) <=0)
					continue;
				service_info_t *srv = NULL;
				srv = g_malloc0(sizeof(service_info_t));
				g_snprintf(srv->ns_name, sizeof(srv->ns_name), "%s",
						gs_get_namespace(container->info.gs));
				g_snprintf(srv->type, sizeof(srv->type), "%s", srvtype);
				addr_info_t *tmp = NULL;
				tmp = _unpack_service(str_srv[i]);
				memcpy(&(srv->addr), tmp, sizeof(addr_info_t));
				if(tmp)
					g_free(tmp);
				list_of_srvinfo = g_slist_prepend(list_of_srvinfo, srv);
			}
			result  = _make_service_array_from_services(container, srvtype, list_of_srvinfo);
			break;
		}
	}

end_label:

	if(exclude) {
		g_slist_foreach(exclude, addr_info_gclean, NULL);
		g_slist_free(exclude);
	}

	if (list_of_srvinfo) {
		g_slist_free(list_of_srvinfo);
	}
	if (gerr)
		g_error_free(gerr);

	if(meta1_addr) 
		g_free(meta1_addr);

	if(str_srv)
		g_strfreev(str_srv);

	return result;
}

