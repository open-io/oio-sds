#include "./gs_internals.h"

#define KEY_STG_POLICY "storage_policy"


/* do not export this function, used only for code factoring
 * file descriptors leaks should be too easy with it */
static gs_status_t gs_container_load (gs_container_t *container, GError **err);

static int _create (gs_container_t *container, struct m2v2_create_params_s *params,
		GError **err, int nb, GSList **exclude, int max);

static int _get (gs_container_t *container, struct m2v2_create_params_s *params,
		GError **err, int nb, int max, int ac);

static addr_info_t *
_update_master(gs_container_t *c, char *master)
{
	GError *e = NULL;
	addr_info_t * new_master = NULL;

	if(!master)
		return NULL;

	char **tok = g_strsplit(master, ":", 2);
	new_master = build_addr_info(tok[0], atoi(tok[1]), &e);

	if( NULL != new_master) {
		gs_update_meta1_master(c->info.gs, C0_ID(c), master);
	}

	g_strfreev(tok);

	if(NULL != e)
		g_clear_error(&e);

	return new_master;

}

static inline int
_is_sql_error(const int errcode)
{
	return errcode > 500 && errcode < 600;
}

static int
__create_in_meta2(addr_info_t *m1, gs_container_t *c, struct m2v2_create_params_s *params, GError **err)
{
	GError *e = NULL;
	addr_info_t *new_master = NULL;
	char *master = NULL;
	int rc = GS_OK;

	/* Check ref exist, create if necessary, link to a meta2 and create meta2_entry */

	/* Useless code, gs_meta1v2 create the reference just before */

	gchar **m2 = NULL;
	m2 = meta1v2_remote_link_service((new_master) ? new_master : m1, &e,
			gs_get_full_vns(c->info.gs), C0_ID(c), "meta2",
			c->info.gs->direct_resolver->timeout.m1.cnx,
			c->info.gs->direct_resolver->timeout.m1.op, &master);
	if( NULL != new_master)
		g_free(new_master);

	new_master = _update_master(c, master);

	if(!m2 || 0 == g_strv_length(m2)) {
		if( NULL != e) {
			GSETCODE(err, e->code, "%s", e->message);
		} else {
			GSETCODE(err, 500, "Failed to link service meta2 , no error specified");
		}
		rc = GS_ERROR;
		goto cleanup_label;
	}

	/* prepare the policies array */
	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, gs_get_full_vns(c->info.gs));
	hc_url_set(url, HCURL_REFERENCE, C0_NAME(c));

	/* parse m2[0] srv to get ip:port  X|meta2|ip:port|... */
	char *p = strchr(strchr(m2[0], '|') + 1, '|') + 1;
	char *end = strchr(p, '|');
	p = g_strndup(p, end - p);

	g_clear_error(&e);
	e = m2v2_remote_execute_CREATE(p, NULL, url, params);

	g_free(p);

	if (NULL != e) {
		GRID_WARN("Failed to create meta2 container: %s",
				e->message);
		GError *e2 = NULL;
		// Rollback meta1 service link
		meta1v2_remote_unlink_service((new_master) ? new_master : m1, &e2,
			gs_get_full_vns(c->info.gs), C0_ID(c), "meta2",
			c->info.gs->direct_resolver->timeout.m1.cnx,
			c->info.gs->direct_resolver->timeout.m1.op, &master);
		if (e2 != NULL) {
			GRID_WARN("Failed to rollback service link: %s", e2->message);
			g_clear_error(&e2);
		}
		GSETCODE(err, e->code, "Failed to create meta2 container: %s" ,
				e->message);
		rc = GS_ERROR;
	}

	g_strfreev(m2);
	hc_url_clean(url);

cleanup_label:
	if (NULL != new_master)
		g_free(new_master);

	if (e != NULL)
		g_clear_error(&e);

	return rc;
}

/**
 * @private
 * Create a distant container and init its reference in the structure
 * @todo TODO this could be factored in meta1utils
 */
static int
_create (gs_container_t *container, struct m2v2_create_params_s *params,
		GError **err, int nb, GSList **exclude, int max)
{
	char str_addr[STRLEN_ADDRINFO];
	addr_info_t m1Addr, *pM1;

	DEBUG("Creation attempt for [%s]", C0_NAME(container));

	if (nb>=max) {
		DEBUG("Too many creation attempts for [%s]", C0_NAME(container));
		GSETERROR(err, "Too many creation attempts");
		return GS_ERROR;
	}

	pM1 = gs_resolve_meta1v2 (container->info.gs, C0_ID(container), C0_NAME(container), 0, *exclude, err);

	if( NULL != *exclude ) {
		g_slist_foreach(*exclude, addr_info_gclean, NULL);
		g_slist_free(*exclude);
		*exclude = NULL;
	}

	if (!pM1) {
		DEBUG("META1 resolution error for [%s]", C0_NAME(container));
		GSETERROR(err, "META1 resolution error for [%s]", C0_NAME(container));
		return GS_ERROR;
	}
	memcpy (&m1Addr, pM1, sizeof(addr_info_t));
	addr_info_to_string (&m1Addr, str_addr, sizeof(str_addr));

	if (__create_in_meta2(&m1Addr, container, params, err)) {
		g_free (pM1);
		DEBUG("Creation successful, now resolving [%s]", C0_NAME(container));
		return _get(container, params, err, 0, NB_ATTEMPTS_GET_CONTAINER, 0/*no more autocreate*/);
	}

	if (err && *err) {
		register int code = (*err)->code;
		if (code==CODE_CONTAINER_EXISTS) {
			g_free (pM1);
			DEBUG("The container has been created by another, we resolve it");
			return _get(container, params, err, 0, NB_ATTEMPTS_GET_CONTAINER, 0/*no more autocreate*/);
		} else if (CODE_REFRESH_META0(code)) {
			g_free (pM1);
			INFO("META0 REFRESH on %s", g_error_get_message(*err));
			gs_decache_all (container->info.gs);
			return _create( container, params, err, nb+1, exclude, max );
		} else if (code < 100) {
			*exclude = g_slist_prepend(*exclude, pM1);
			DEBUG("Local/Network error, retrying the creation of [%s]", C0_NAME(container));
			gs_decache_all (container->info.gs);
			return _create( container, params, err, nb+1, exclude, max );
		} else {
			g_free (pM1);
			DEBUG("META0 refresh impossible for [%s]", C0_NAME(container));
			GSETERROR(err, "Failed to create container [%s] on META1=[%s]", C0_NAME(container), str_addr);
			return GS_ERROR;
		}
	}

	g_free (pM1);

	/* no retry possible */
	TRACE("Unknown error for [%s]", C0_NAME(container));
	GSETERROR(err, "Cannot autocreate [%s] on META1=[%s] (unknown error)", C0_NAME(container), str_addr);
	return GS_ERROR;
}

/* Get the reference of the container and create it (if wanted) */
static int
_get (gs_container_t *container, struct m2v2_create_params_s *params,
		GError **err, int retry_count, int max_retries, int ac)
{

	DEBUG("Resolution attempt NAME=[%s] ID=[%s]", C0_NAME(container), C0_IDSTR(container));

	if (retry_count >= max_retries) {
		GSETERROR(err,"Too many resolution attempts");
		return GS_ERROR;
	}

	if (gs_container_load( container, err )) {
		if (err)
			g_clear_error(err);
		return GS_OK;
	}

	if (!err || !*err) {
		GSETERROR(err,"Unknown error");
		gs_decache_container (container->info.gs, C0_ID(container));
		return GS_ERROR;
	}

	TRACE("### container loading error %d", (*err)->code);

	if ((*err)->code == CODE_CONTAINER_NOTFOUND) {
		if (!ac) {
			TRACE("No autocreation");
			gs_decache_container (container->info.gs, C0_ID(container));
			return GS_ERROR;
		} else {
			g_clear_error(err);
			GSList *exclude = NULL;
			int r = _create(container, params, err, 0, &exclude, NB_ATTEMPTS_AUTOCREATE);
			if (NULL != exclude) {
				g_slist_foreach(exclude, addr_info_gclean, NULL);
				g_slist_free(exclude);
			}
			return r;
		}
	}

	gs_decache_container (container->info.gs, C0_ID(container));

	if ((*err)->code < 100)
		return _get( container, params, err, retry_count + 1, max_retries, ac );

	GSETERROR(err,"Unmanageable error on ID=[%s]", C0_IDSTR(container));
	return GS_ERROR;
}

static int
container_resolve_and_get (gs_container_t *container, struct m2v2_create_params_s *params,
		int auto_create, GError **err)
{
	return _get( container, params, err, 0, NB_ATTEMPTS_GET_CONTAINER, auto_create );
}

static int
container_resolve_and_get_v2 (gs_container_t *container, GError **err)
{
	int status = GS_ERROR;
	DEBUG("Resolution attempt NAME=[%s] ID=[%s]", C0_NAME(container), C0_IDSTR(container));

	/* resolve_meta1 + has */
	addr_info_t *meta1_addr = NULL;
	GSList *exclude_m1 = NULL;
	int retry = 3;

	while(retry > 0) {
		retry--;
		meta1_addr = gs_resolve_meta1v2_v2(container->info.gs, C0_ID(container),
				C0_NAME(container), 1, exclude_m1, TRUE, err);

		if(!meta1_addr) {
			GSETERROR(err, "Failed to resolve Meta1");
			goto end;
		}

		if (*err) {
			if ((*err)->code != CODE_CONTAINER_EXISTS) {
				/* consider hard error, try on another M1 */
				exclude_m1 = g_slist_prepend(exclude_m1, meta1_addr);
				meta1_addr = NULL;
			} else {
				g_clear_error(err);
			}
		}

		if (NULL == *err) {
			status = GS_OK;
			break;
		}
	}

end:

	if(exclude_m1) {
		g_slist_foreach(exclude_m1, addr_info_gclean, NULL);
		g_slist_free(exclude_m1);
	}

	if(meta1_addr) {
		g_free(meta1_addr);
	}

	return status;
}

void
fill_hcurl_from_container(gs_container_t *c, struct hc_url_s **url)
{
	*url = hc_url_empty();
	hc_url_set(*url, HCURL_NS, gs_get_full_vns(c->info.gs));
	hc_url_set(*url, HCURL_REFERENCE, C0_NAME(c));
}

gs_container_t*
gs_init_container(gs_grid_storage_t *gs, const char *cname, int ac, gs_error_t **gs_err)
{
	gs_container_t *container = NULL;
	size_t nLen;

	g_assert(gs != NULL);
	g_assert(cname != NULL);

	nLen = strlen(cname);
	if (nLen > sizeof(container->info.name)-1) {
		GSERRORSET(gs_err,"Container name too long");
		return NULL;
	}

	/*allocates and init the structure*/
	container = calloc(1, sizeof(gs_container_t));
	if (!container) {
		GSERRORSET(gs_err,"Memory allocation failure");
		return NULL;
	}

	container->meta2_cnx = -1;
	container->info.gs = gs;
	memcpy(container->info.name, cname, nLen);

	meta1_name2hash(container->cID, gs_get_full_vns(gs), C0_NAME(container));
	container_id_to_string( container->cID, container->str_cID, sizeof(container->str_cID) );
	container->ac = ac;

	return container;
}

gs_container_t*
gs_get_container (gs_grid_storage_t *gs, const char *container_name,
		int auto_create, gs_error_t **gs_err)
{
	GError *localError = NULL;
	gs_container_t *container=NULL;

	/*sanity checks*/
	if (!gs || !container_name) {
		GSERRORSET(gs_err, "invalid parameter");
		return NULL;
	}

	container = gs_init_container(gs, container_name, auto_create, gs_err);
	if (!container)
		return NULL;

	/* only ensure directory part */
	if (GS_ERROR == container_resolve_and_get_v2(container, &localError)) {
		if (!localError)
			GSETERROR(&localError,"Failed to resolve container [%s]", C0_NAME(container));
		goto error_label;
	}

	if (localError)
		g_clear_error(&localError);

	return container;

error_label:

	if (container)
		gs_container_free (container);
	if (!localError)
		GSETERROR(&localError,"unknown error");
	GSERRORCAUSE(gs_err,localError,"Failed to get container [%s]", container_name);
	g_clear_error(&localError);
	return NULL;
}


gs_container_t*
gs_get_container_by_hexid (gs_grid_storage_t *gs, const char *hex_id, int auto_create, gs_error_t **gs_err)
{
	struct m2v2_create_params_s params = {NULL,NULL, FALSE};
	GError *localError = NULL;
        gs_container_t *container=NULL;

        /*sanity checks*/
        if (!gs || !hex_id) {
                GSERRORSET(gs_err, "invalid parameter");
                return NULL;
        }

        /*allocates and init the structure*/
        container = calloc (1, sizeof(gs_container_t));
        if (!container)
        {
                GSERRORSET(gs_err,"Memory allocation failure");
                return NULL;
        }
        else
        {
                /*copy the id of the container*/
                g_strlcpy(container->str_cID, hex_id, sizeof(container->str_cID));
                container_id_hex2bin(hex_id, strlen(hex_id), &(container->cID), NULL);

                /*link the container to its grid_storage client structure*/
                container->info.gs = gs;
                container->meta2_cnx = -1;
        }

        TRACE("hash done : name=[%s] -> id=[%s]", C0_NAME(container), C0_IDSTR(container));

        /*get the container location*/
        if (GS_ERROR == container_resolve_and_get(container, &params, auto_create, &localError)) {
                if (!localError)
                        GSETERROR(&localError,"Failed to resolve container [%s]", C0_NAME(container));
                goto error_label;
        }

        if (localError)
                g_clear_error(&localError);

        return container;
error_label:
        if (container)
                gs_container_free (container);
        if (!localError)
                GSETERROR(&localError,"unknown error");
        GSERRORCAUSE(gs_err,localError,"Failed to get container [%s]", hex_id);
        g_clear_error(&localError);
        return NULL;
}


int
gs_container_is_open (gs_container_t *container, gs_error_t **err)
{
	(void) err;
	return container ? container->opened : -1;
}


gs_status_t
gs_close_container (gs_container_t *container, gs_error_t **err)
{
	(void) err;
	if (container)
		container->opened = 0;
	return GS_OK;
}

gs_status_t
gs_open_container (gs_container_t *container, gs_error_t **err)
{
	(void) err;
	if (container)
		container->opened = 1;
	return GS_OK;
}

static path_info_t *
_alias_to_path_info(gpointer alias)
{
	if(DESCR(alias) != &descr_struct_ALIASES) {
		/* invalid bean */
		return NULL;
	}
	struct bean_ALIASES_s *a = (struct bean_ALIASES_s *) alias;
	path_info_t *pi = g_malloc0(sizeof(path_info_t));
	memset(pi->path, '\0', sizeof(pi->path));
	char * str = ALIASES_get_alias(a)->str;
	g_snprintf(pi->path, sizeof(pi->path), "%s", str);
	pi->size = 0;
	pi->hasSize = FALSE;
	pi->user_metadata = NULL;
	pi->system_metadata = g_byte_array_append(g_byte_array_new(), (const guint8*)ALIASES_get_mdsys(alias)->str, ALIASES_get_mdsys(alias)->len);
	char tmp[64];
	memset(tmp, '\0', 64);
	g_snprintf(tmp, 64, "%"G_GINT64_FORMAT, ALIASES_get_version(alias));
	pi->version = g_strdup(tmp);
	pi->deleted = ALIASES_get_deleted(alias);

	pi->system_metadata = g_byte_array_append(pi->system_metadata, (const guint8*) tmp, strlen(tmp));
	return pi;
}

static GSList *
_list_v2_wrapper(gs_container_t *c, const char *version, GError **e)
{
	GSList *beans = NULL;
	GError *le = NULL;
	GSList *l, *result = NULL;

	char target[64];
	bzero(target, sizeof(target));
	addr_info_to_string(&(c->meta2_addr), target, 64);

	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, gs_get_full_vns(c->info.gs));
	hc_url_set(url, HCURL_REFERENCE, C0_NAME(c));
	if (version != NULL)
		hc_url_set(url, HCURL_SNAPORVERS, version);

	le = m2v2_remote_execute_LIST(target, NULL, url, M2V2_FLAG_ALLVERSION, &beans);

	hc_url_clean(url);

	if(NULL != le) {

		if (!*e) {
			*e = NEWERROR(le->code, "%s", le->message);
		} else {
			g_prefix_error(e, "\n\t%s", le->message);
			(*e)->code = le->code;
		}
		g_clear_error(&le);
		return NULL;
	}

	/* now we has aliases of all existing version of contents in the targeted container */
	for(l = beans; l && l->data; l = l->next) {
		path_info_t *pi = _alias_to_path_info(l->data);
		if(NULL != pi) {
			result = g_slist_prepend(result, pi);
		}
	}

	_bean_cleanl2(beans);
	return result;
}

gs_status_t
gs_list_container(gs_container_t *container, gs_content_t*** result,
		gs_content_filter_f filter, void *user_data, gs_error_t **err)
{
	return gs_list_container_snapshot(container, result, filter, user_data,
			NULL, err);
}

gs_status_t
gs_list_container_snapshot(gs_container_t *container, gs_content_t*** result,
		gs_content_filter_f filter, void *user_data, const char *snapshot,
		gs_error_t **err)
{
	gs_status_t rc = GS_ERROR;
	int nbResult, nb_refreshes;
	GError *localError = NULL;
	GSList *contents = NULL, *current = NULL;

	/*sanity checks*/
	if (!container || !container->info.gs) {
		GSERRORSET(err, "invalid parameter");
		return 0;
	}

	/* loop until the listing is got or too many attempts happen */
	(void) gs_container_reconnect_if_necessary (container, NULL);
	for (nb_refreshes = 2; nb_refreshes > 0; nb_refreshes--)
	{
		g_clear_error(&localError);
		contents = _list_v2_wrapper(container, snapshot, &localError);
		if (!contents && localError) {
			if (localError->code == CODE_CONTAINER_NOTFOUND) {
				GRID_DEBUG("Decaching container '%s'", container->info.name);
				gs_decache_container(container->info.gs, C0_ID(container));
			}
			CONTAINER_REFRESH(container, localError, end_label,
					"cannot list the content");
		} else {
			break;
		}
	}

	/*it is NOT an error if*/
	if (!contents && !localError)
		return(1);

	if (!contents && localError)
		goto end_label;

	if (localError)
		g_clear_error(&localError);


	/*
	 * USE THE RESULT
	 */
	if (result) {
		nbResult = 0;
		*result = calloc (1,sizeof(gs_content_t*));
		if (!*result) {
			GSETERROR(&localError,"Memory allocation failure");
			goto end_label;
		}
	}

	for (nbResult=0, current=contents; current ; current=current->next)
	{
		path_info_t *pi = NULL;
		gs_content_t *content = NULL;

		pi = (path_info_t*) current->data;
		if (!pi) {
			WARN("EMPTY CONTENT from meta2_remote_content_retrieve_in_fd return");
			continue;
		}

		content = calloc(1, sizeof(gs_content_t));
		if (!content) {
			GSETERROR(&localError,"Memory allocation failure");
			goto end_label;
		}

		content->chunk_list = NULL;
		content->info.container = container;
		memset (content->info.path, 0x00, sizeof(content->info.path));
		memcpy (content->info.path, pi->path, MIN(sizeof(content->info.path)-1,sizeof(pi->path)-1));
		content->info.size = pi->hasSize ? pi->size : -1;
		if(NULL != pi->system_metadata)
			content->gba_sysmd = g_byte_array_append(g_byte_array_new(), pi->system_metadata->data, pi->system_metadata->len);
		if(NULL != pi->version)
			content->version = g_strdup(pi->version);
		content->deleted = pi->deleted;

		if (filter)
		{
			int localRC;
			switch ((localRC = filter (content, user_data)))
			{
				case 0:
					gs_content_free (content);
					break;
				case 1:
					if (result)
					{
						gs_content_t ** newTab = realloc(*result,
								(nbResult+1)*sizeof(gs_content_t*));
						if (!newTab)
						{
							GSETERROR(&localError, "Memory allocation failure (%s)", strerror(errno));
							goto end_label;
						}
						newTab [nbResult-1] = content;
						newTab [nbResult] = NULL;
						*result = newTab;
						nbResult ++;
					}
					break;
				case -1:
					gs_content_free(content);
					GSETERROR(&localError,"the user filter failed");
					goto end_label;
				default:
					gs_content_free(content);
					GSETERROR(&localError,"bad return code from the user filter (%i)", localRC);
					goto end_label;
			}
		} else if (result)
		{
			gs_content_t ** newTab = realloc(*result, (nbResult+1)*sizeof(gs_content_t*));
			if (!newTab) {
				GSETERROR(&localError, "Memory allocation failure (%s)", strerror(errno));
				goto end_label;
			}
			newTab [nbResult-1] = content;
			newTab [nbResult] = NULL;
			*result = newTab;
			nbResult ++;
		}
	}

	rc=GS_OK;
end_label:
	if (contents) {
		g_slist_foreach (contents, path_info_gclean, NULL);
		g_slist_free (contents);
	}
	if (!rc) {
		if (result && *result) {
			gs_content_t **c;
			for (c=*result; c && *c ;c++)
				gs_content_free (*c);
			free(*result);
		}
		if (!localError)
			GSETERROR(&localError,"unknown error");
		GSERRORCAUSE(err,localError,"Cannot list the content of %s/%s", C0_NAME(container), C0_IDSTR(container));
	}
	if (localError)
		g_clear_error(&localError);
	return rc;
}

gs_content_t*
gs_get_content_from_path (gs_container_t *container, const char *name, gs_error_t **err)
{
	return gs_get_content_from_path_full(container, name, NULL, NULL, NULL, err);
}

gs_content_t*
gs_get_content_from_path_and_version (gs_container_t *container, const char *name, const char *version,
		gs_error_t **err)
{
	return gs_get_content_from_path_full(container, name, version, NULL, NULL, err);
}

gs_content_t*
gs_get_content_from_path_full (gs_container_t *container, const char *name, const char *version,
		void *_p_filtered, void *_p_beans, gs_error_t **err)
{
	gs_content_t *content;
	GSList **p_filtered = _p_filtered;
	GSList **p_beans = _p_beans;

	if (!container || !name || !*name) {
		GSERRORSET(err, "invalid parameter");
		return NULL;
	}

	if (!(content=calloc(1,sizeof(gs_content_t)))) {
		GSERRORSET(err, "Memory allocation failure");
		return NULL;
	}
	content->version = NULL;
	g_strlcpy(content->info.path, name, sizeof(content->info.path)-1);
	content->info.container = container;
	if (NULL != version && strlen(version) > 0) {
		content->version = g_strdup(version);
	}

	if (!gs_content_reload_with_filtered(content, TRUE, FALSE, p_filtered, p_beans, err)) {
		gs_content_free(content);
		return NULL;
	}
	// Version will be set to 1 for containers for which versioning in not active.
	// If we asked for a content with no version specified, we do mean no version.
	if (NULL == version) {
		g_free(content->version);
		content->version = NULL;
	}
	return content;
}


static int
gs_container_check_cnx (gs_container_t *container)
{
	if (!container)
		return 0;
	if (container->meta2_cnx < 0)
		return 0;
	if (!sock_get_error(container->meta2_cnx))
		return 1;

	if (errno == EBADF)
		container->meta2_cnx = -1;
	return 0;
}

static gs_status_t
gs_container_load (gs_container_t *container, GError **err)
{
	gs_status_t rs=GS_ERROR;
	GSList *m2Locations=NULL;
	GSList *locationCursor=NULL;

	/* ensure we won't leak with this file_descriptor */
	gs_container_close_cnx (container);

	/**/
	m2Locations = gs_resolve_meta2 (container->info.gs, C0_ID(container), err);
	if (!m2Locations) {
		GSETERROR(err,"Resolution error for NAME=[%s] ID=[%s]", C0_NAME(container), C0_IDSTR(container));
		return GS_ERROR;
	}

	/* Tries to find a good META2
	 * At this point, META2 addresses have been received, so the META1
	 * was the good one (if it was not the case, it MUST NOT HAVE ANSWERED). */

	for ( locationCursor = m2Locations
			; locationCursor!=NULL && container->meta2_cnx < 0
			; locationCursor = locationCursor->next )
	{
		char str_addr[STRLEN_ADDRINFO];

		addr_info_t *m2addr = (addr_info_t*) locationCursor->data;
		addr_info_to_string (m2addr, str_addr, sizeof(str_addr));
		DEBUG("Trying to connect to meta2 [%s]", str_addr);

		/*update the address of the container*/
		g_memmove(&(container->meta2_addr), m2addr, sizeof(addr_info_t));

		/*contact the META2*/
		if (gs_container_reconnect_and_refresh(container,err,FALSE))
			break;

		WARN("cannot connect to META2=%s for %s/%s (%s)",
				str_addr, C0_NAME(container), C0_IDSTR(container),
				err ? g_error_get_message(*err) : "error not set");
	}

	/* After all, if no connection can be opened, it is a strong error */
	if (!gs_container_check_cnx(container)) {
		GSETERROR(err, "no META2 accepted to serve %s/%s", C0_NAME(container), C0_IDSTR(container));
	} else {
		rs = (*err == NULL);
	}

	g_slist_foreach (m2Locations, addr_info_gclean, NULL);
	g_slist_free (m2Locations);
	return rs;
}

gs_status_t
gs_container_reconnect_and_refresh (gs_container_t *container, GError **err, gboolean may_refresh)
{
	/*sanity checks*/
	if (!container) {
		GSETERROR(err, "invalid parameter");
		return GS_ERROR;
	}

	/*open and check the connection*/
	container->meta2_cnx = addrinfo_connect (&(container->meta2_addr), C0_M2TO_CNX(container), err);

	if (!gs_container_check_cnx(container)) {
		/*the connection failed*/
		if (!may_refresh) {
			GSETERROR(err, "Not authorized to refresh once again the meta2 reference for %s/%s", C0_NAME(container), C0_IDSTR(container));
			return GS_ERROR;
		}
		if (!gs_container_refresh (container, err)) {
			GSETERROR(err, "Cannot reconnect/refresh to meta2 for %s/%s", C0_NAME(container), C0_IDSTR(container));
			return GS_ERROR;
		}
	}

	// Checking connection is not sufficient (is it even useful?),
	// we must check if container is there.
	gchar addr[STRLEN_ADDRINFO];
	addr_info_to_string(&(container->meta2_addr), addr, STRLEN_ADDRINFO);
	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, gs_get_full_vns(container->info.gs));
	hc_url_set(url, HCURL_HEXID, container->str_cID);
	*err = m2v2_remote_execute_HAS(addr, NULL, url);
	hc_url_clean(url);
	if (*err) {
		metautils_pclose(&(container->meta2_cnx));
		return GS_ERROR;
	}

	/*the connection succeeded*/
	return GS_OK;
}


gs_status_t
gs_container_refresh (gs_container_t *container, GError **err)
{
	gs_status_t rs=GS_ERROR;

	if (!container) {
		GSETERROR(err, "Invalid argument");
		return GS_ERROR;
	}

	gs_decache_container (container->info.gs, C0_ID(container));

	rs = gs_container_load( container, err );
	if (rs!=GS_OK)
		GSETERROR(err,"refresh failure");
	return rs;
}


gs_status_t
gs_container_reconnect (gs_container_t *container, GError **err)
{
	gs_container_close_cnx (container);
	return gs_container_reconnect_and_refresh (container, err, TRUE);
}


gs_status_t
gs_container_reconnect_if_necessary (gs_container_t *container, GError **err)
{
	return gs_container_check_cnx(container) ? GS_OK : gs_container_reconnect (container, err);
}

static GError*
_allm2(gs_container_t *container, gchar ***targets)
{
	gchar **p;
	GError *err = NULL;

	GSList *l, *allm2 = resolver_direct_get_meta2(container->info.gs->direct_resolver,
			container->info.gs->physical_namespace, C0_ID(container), &err, 4);
	if (err != NULL)
		return err;

	guint len = g_slist_length(allm2);

	*targets = g_malloc0(sizeof(gchar*) * (len+1));
	for (l=allm2,p=*targets; l ;l=l->next,p++) {
		struct addr_info_s *ai;
		if (NULL != (ai = l->data)) {
			gchar straddr[STRLEN_ADDRINFO+1];
			addr_info_to_string(l->data, straddr, sizeof(straddr));
			*p = g_strdup(straddr);
		}
	}

	g_slist_free_full(allm2, g_free);
	return NULL;
}

static GError*
_destroy_on_allm2(gs_container_t *container, guint32 flags)
{
	gchar **targets = NULL;
	GError *err = NULL;

	if (NULL != (err = _allm2(container, &targets)))
		return err;

	if (!targets)
		return NEWERROR(CODE_CONTAINER_NOTFOUND, "No such container");

	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, gs_get_full_vns(container->info.gs));
	hc_url_set(url, HCURL_REFERENCE, C0_NAME(container));
	hc_url_set(url, HCURL_HEXID, container->str_cID);

	// Starting from 1.8.3.10, destroy event is called on slaves by the master
	err = m2v2_remote_execute_DESTROY(targets[0], NULL, url, flags);
	g_strfreev(targets);

	return err;
}

static GError*
_destroy_everywhere(gs_container_t *container, GSList **exclude, guint32 flags)
{
	GError *err = NULL;

	// Whatever happen, decache this shitty container!
	gs_decache_container(container->info.gs, C0_ID(container));

	// Locate the meta2 and send the destruction command
	if (NULL != (err = _destroy_on_allm2(container, flags))) {
		g_prefix_error(&err, "Failed on some M2: ");
		return err;
	}

	/* if ok, drop m2 link */
	struct addr_info_s *m1 = gs_resolve_meta1v2(container->info.gs,
			C0_ID(container), NULL, 0, *exclude, &err);

	if (!m1) {
		if (!err)
			err = NEWERROR(500, "Unknown error");
		g_prefix_error(&err, "META0/1 error: ");
	}
	else {
		if (!meta1v2_remote_unlink_service(m1, &err,
				gs_get_full_vns(container->info.gs),
				C0_ID(container), "meta2", 10000, 30000, NULL))
			g_prefix_error(&err, "META0/1 unlink error: ");
		g_free(m1);
	}
	return err;
}

gs_status_t
gs_destroy_container (gs_container_t *container, gs_error_t **err)
{
	return gs_destroy_container_flags(container, 0, err);
}

gs_status_t
gs_destroy_container_flags (gs_container_t *container, unsigned int flags,
		gs_error_t **err)
{
	GError *e = NULL;
	GSList *m1_exclude = NULL;

	for (int max=3; max > 0 ;--max) {
		if (e)
			g_clear_error(&e);

		if (!(e = _destroy_everywhere(container, &m1_exclude, (guint32)flags)))
			goto success;
		if (e->code == CODE_CONTAINER_NOTFOUND)
			goto success;
		if (e->code == CODE_CONTAINER_NOTEMPTY)
			break;
	}

	// ERROR
	if (!e)
		g_prefix_error(&e, "Various errors");
	GSERRORCAUSE(err,e, "Cannot destroy the container");
	g_clear_error(&e);
	g_slist_free_full(m1_exclude, g_free);
	return GS_ERROR;

success:
	if (e)
		g_clear_error(&e);
	g_slist_free_full(m1_exclude, g_free);
	return GS_OK;
}


gs_status_t
gs_flush_container (gs_container_t *container, gs_error_t **err)
{
	GError *gerr=NULL;

	/* this callback will be applied on each content. It destroys the
	 * remote content and free the structure */
	int _filter (gs_content_t *content, void *user_data)
	{
		gs_status_t rc;
		gs_error_t *e=NULL;
		(void)user_data;
		int attempts=2;

		gs_status_t _flusher (void)
		{
			if ((attempts--)<=0)
			{
				GSETERROR(&gerr,"too many attempts");
				return GS_ERROR;
			}

			if (GS_OK != gs_destroy_content(content, &e))
			{
				TRACE("attempt failed");
				return _flusher();
			} else return GS_OK;
		}

		/*first recursive call on the flusher function*/
		if (GS_OK != _flusher())
		{
			/*the whole recursion failed, map the error and exit*/
			GSETERROR(&gerr,"cannot flush the content : %s", gs_error_get_message(e));
			rc = -1;
		} else rc = 1;

		if (e)
			gs_error_free (e);
		return rc;
	}

	/*sanity checks*/
	if (!container) {
		GSETERROR(&gerr, "invalid parameter (null container)");
		return GS_ERROR;
	}

	/* run the list with our custom filter. it does not matter if we do
	 * not store the contents, they will be freed */
	if (GS_OK != gs_list_container(container, NULL, _filter, NULL, err)) {
		if (!gerr) GSETERROR(&gerr,"unknown cause");
		GSERRORCAUSE(err, gerr,"cannot run the content's list : %s", g_error_get_message(gerr));
		g_clear_error(&gerr);
		return GS_ERROR;
	} else {
		if (gerr) g_clear_error(&gerr);
		return GS_OK;
	}
}


gs_status_t
gs_container_get_info (const gs_container_t *container,
	gs_container_info_t *info, gs_error_t **err)
{
	if (!container || !info)
	{
		GSERRORSET(err,"invalid parameter");
		return GS_ERROR;
	}
	memcpy (info, &(container->info), sizeof(gs_container_info_t));
	return GS_OK;
}

gs_status_t
gs_download_content_by_name(gs_container_t *container, const char *name,
		gs_download_info_t *dl_info, gs_error_t **err)
{
	return gs_download_content_by_name_full(container, name, NULL, NULL, dl_info, err);
}

gs_status_t
gs_download_content_by_name_and_version(gs_container_t *container, const char *name, const char *version,
		gs_download_info_t *dl_info, gs_error_t **err)
{
	return gs_download_content_by_name_full(container, name, version, NULL, dl_info, err);
}

gs_status_t
gs_download_content_by_name_full(gs_container_t *container, const char *name, const char *version,
	const char *stgpol, gs_download_info_t *dl_info, gs_error_t **err)
{
	int rc = GS_ERROR;
	gs_content_t *content = NULL;
	gs_error_t *gserr_cache = NULL;

	if (!container || !name || !*name) {
		GSERRORSET(err,"invalid parameter");
		return GS_ERROR;
	}

	if (!(content=calloc(1,sizeof(gs_content_t)))) {
		GSERRORSET(err, "Memory allocation failure");
		return GS_ERROR;
	}
	g_strlcpy(content->info.path, name, sizeof(content->info.path)-1);
	content->info.container = container;
	if (version && *version)
		content->version = g_strdup(version);

	/* If the content can be entirely loaded from the cache,
	 * directly try the download */

	if (gs_content_reload(content, FALSE, TRUE, &gserr_cache)) {
		if(content->deleted) {
			GSERRORCODE(err, CODE_CONTENT_NOTFOUND, "Content deleted");
			gs_content_free(content);
			return GS_ERROR;
		} else{
			INFO("Chunks loaded from the metacd");
			if (gs_download_content_full(content, dl_info, stgpol, NULL, NULL, &gserr_cache)) {
				/* SUCCESS */
				gs_content_free(content);
				if (gserr_cache)
					gs_error_free(gserr_cache);
				return GS_OK;
			}
			else {
				/* FAILURE */
				GSERRORSET(&gserr_cache, "dl error");
				if (err)
					*err = gserr_cache;
				else if (gserr_cache)
					gs_error_free(gserr_cache);
				gs_content_free(content);
				return GS_ERROR;
			}
		}
	}

	/* Regular download */
	if (!gs_content_reload(content, TRUE, FALSE, err)) {
		GSERRORSET(err, "Implicit content loading failure");
		goto error_opened;
	}
	if(content->deleted) {
		GSERRORCODE(err, CODE_CONTENT_NOTFOUND, "Content deleted");
		goto error_opened;
	}

	if (!gs_download_content_full(content, dl_info, stgpol, NULL, NULL, err)) {
		GSERRORSET(err, "Download failure");
		goto error_opened;
	}

	rc = GS_OK;
error_opened:
	gs_content_free(content);
	if (gserr_cache)
		gs_error_free(gserr_cache);
	return rc;
}

gs_status_t
gs_delete_content_by_name(gs_container_t *container, const char *name, gs_error_t **err)
{
	int rc = GS_ERROR;
	gs_content_t *content;

	if (!container || !name || !*name) {
		GSERRORSET(err,"invalid parameter");
		return GS_ERROR;
	}

	if (!(content=calloc(1,sizeof(gs_content_t)))) {
		GSERRORSET(err, "Memory allocation failure");
		return GS_ERROR;
	}
	g_strlcpy(content->info.path, name, sizeof(content->info.path)-1);
	content->info.container = container;

	if (!gs_content_reload(content, TRUE, FALSE, err)) {
		GSERRORSET(err, "Implicit content loading failure");
		goto error_opened;
	}
	if (!gs_destroy_content(content, err)) {
		GSERRORSET(err, "Download failure");
		goto error_opened;
	}
	rc = GS_OK;

error_opened:
	gs_content_free(content);
	return rc;
}
/* Improved version of gs_get_storage_container */
gs_container_t*
gs_get_storage_container2(gs_grid_storage_t *gs, const char *container_name,
		struct m2v2_create_params_s *params, int auto_create, gs_error_t **gs_err)
{
	GError *localError = NULL;
	gs_container_t *container=NULL;

	/*sanity checks*/
	if (!gs || !container_name) {
		GSERRORSET(gs_err, "invalid parameter");
		return NULL;
	}

	TRACE("get container [%s]", container_name);

	/*allocates and init the structure*/
	container = calloc (1, sizeof(gs_container_t));
	if (!container)
	{
		GSERRORSET(gs_err,"Memory allocation failure");
		return NULL;
	}
	else
	{
		size_t nLen;

		/*copy the name of the container*/
		nLen = strlen(container_name);
		if (nLen>sizeof(container->info.name)-1)
			nLen = sizeof(container->info.name)-1;

		memcpy(container->info.name, container_name, nLen);

		/*hash the name*/
		meta1_name2hash(container->cID, gs_get_full_vns(gs), C0_NAME(container));

		/*pre-set the string form of the container id */
		container_id_to_string( container->cID, container->str_cID, sizeof(container->str_cID) );

		/*link the container to its grid_storage client structure*/
		container->info.gs = gs;
		container->meta2_cnx = -1;
	}

	TRACE("hash done : name=[%s] -> id=[%s]", C0_NAME(container), C0_IDSTR(container));

	/*get the container location*/
	if (GS_ERROR == container_resolve_and_get(container, params, auto_create, &localError)) {
		if (!localError)
			GSETERROR(&localError,"Failed to resolve container [%s]", C0_NAME(container));
		goto error_label;
	}

	/* TODO: Add meta2 informations... */

	if (localError)
		g_clear_error(&localError);

	return container;
error_label:
	if (container)
		gs_container_free (container);
	if (!localError)
		GSETERROR(&localError,"unknown error");
	GSERRORCAUSE(gs_err,localError,"Failed to get container [%s]", container_name);
	g_clear_error(&localError);
	return NULL;
}

gs_container_t*
gs_get_storage_container (gs_grid_storage_t *gs, const char *container_name,
		const char *stgpol, int auto_create, gs_error_t **gs_err)
{
	struct m2v2_create_params_s params = {stgpol, NULL, FALSE};
	return gs_get_storage_container2(gs, container_name, &params, auto_create,
			gs_err);
}


gs_container_t* 
gs_get_storage_container_v2(gs_grid_storage_t *gs,
        const char *container_name, const char *stgpol, const char *verspol, 
		int auto_create, gs_error_t **gs_err)
{
    struct m2v2_create_params_s params = {stgpol, verspol, FALSE};
    return gs_get_storage_container2(gs, container_name, &params, auto_create,
	            gs_err);
}


char **
hc_get_container_admin_entries(gs_container_t *container, gs_error_t **gs_err)
{
	GError *localError = NULL;

	/*sanity checks*/
	if (!container) {
		GSERRORSET(gs_err, "invalid parameter");
		return NULL;
	}
	TRACE("get container admin entries [%s]", C0_NAME(container));

	// FIXME TODO This function has been commented and does not do anything

	if (!localError)
		GSETERROR(&localError,"unknown error");
	GSERRORCAUSE(gs_err,localError,"Failed to get container admin entries [%s]", C0_NAME(container));
	g_clear_error(&localError);
	return NULL;
}

static gs_error_t*
_hc_set_container_global_property(gs_container_t *container,
		const char *prop_name, const char *prop_val, gboolean no_check)
{
	gs_error_t *result = NULL;
	GError *g_error = NULL;
	struct hc_url_s *url = NULL;
	gchar m2_url[STRLEN_ADDRINFO];
	struct bean_PROPERTIES_s *bp = NULL;
	GSList *beans = NULL;

	if (!container) {
		char buf[256];
		bzero(buf, sizeof(buf));
		g_snprintf(buf, sizeof(buf) - 1, "Invalid parameter (%p | %s)",
				container, prop_val);
		result = g_malloc0(sizeof(gs_error_t));
		result->code = 400;
		result->msg = g_strdup(buf);
		return result;
	}

	addr_info_to_string(&(container->meta2_addr), m2_url, STRLEN_ADDRINFO);
	fill_hcurl_from_container(container, &url);

	bp = _bean_create(&descr_struct_PROPERTIES);
	PROPERTIES_set2_key(bp, prop_name);
	if (prop_val != NULL) {
		PROPERTIES_set2_value(bp, (guint8*)prop_val, strlen(prop_val));
	} else {
		PROPERTIES_set2_value(bp, (const guint8*)"", 0);
		PROPERTIES_set_deleted(bp, TRUE);
	}
	beans = g_slist_prepend(beans, bp);

	g_error = m2v2_remote_execute_PROP_SET(m2_url, NULL, url,
			no_check? M2V2_FLAG_NOFORMATCHECK : 0, beans);

	if (g_error) {
		result = g_malloc0(sizeof(gs_error_t));
		result->code = g_error->code;
		result->msg = g_strdup(g_error->message);
		g_clear_error(&g_error);
	}

	_bean_cleanl2(beans);
	hc_url_clean(url);
	return result;
}

gs_error_t*
hc_set_container_global_property(gs_container_t *container,
		const char *prop_name, const char *prop_val)
{
	return _hc_set_container_global_property(container, prop_name, prop_val,
			FALSE);
}

gs_error_t*
hc_del_container_global_property(gs_container_t *container,
		const char *prop_name)
{
	return _hc_set_container_global_property(container, prop_name, NULL, FALSE);
}

gs_error_t*
hc_get_container_global_properties(gs_container_t *container, char ***result)
{
	GError *g_error = NULL;
	struct hc_url_s *url = NULL;
	gchar m2_url[STRLEN_ADDRINFO];
	gs_error_t *err = NULL;
	GSList *beans = NULL;
	gint pos = 0;

	addr_info_to_string(&(container->meta2_addr), m2_url, STRLEN_ADDRINFO);
	fill_hcurl_from_container(container, &url);

	g_error = m2v2_remote_execute_PROP_GET(m2_url, NULL, url, 0, &beans);
	if (g_error) {
		err = g_malloc0(sizeof(gs_error_t));
		err->code = g_error->code;
		err->msg = g_strdup(g_error->message);
		g_clear_error(&g_error);
	} else {
		*result = g_malloc0((g_slist_length(beans)+1) * sizeof(gchar *));
		for (GSList *l = beans; l != NULL; l = l->next) {
			GByteArray *val = PROPERTIES_get_value(l->data);
			char buf[val->len + 1];
			memset(buf, '\0', sizeof(buf));
			g_snprintf(buf, sizeof(buf), "%s", val->data);
			(*result)[pos++] = g_strdup_printf("%s=%s",
					PROPERTIES_get_key(l->data)->str, buf);
		}
		_bean_cleanl2(beans);
	}

	hc_url_clean(url);
	return err;
}

gs_error_t*
hc_set_container_storage_policy(gs_container_t *container,
		const char *storage_policy)
{
	GError *ge = NULL;
	char target[64];
	struct hc_url_s *url;

	memset(target, '\0', 64);
	addr_info_to_string(&(container->meta2_addr), target, 64);
	url = hc_url_empty();
	hc_url_set(url, HCURL_NS, gs_get_full_vns(container->info.gs));
	hc_url_set(url, HCURL_REFERENCE, C0_NAME(container));

	if (NULL != (ge = m2v2_remote_execute_STGPOL(target, NULL, url,
			storage_policy, NULL))) {
		gs_error_t *result = g_malloc0(sizeof(gs_error_t));
		result->code = ge->code;
		result->msg = g_strdup(ge->message);
		g_clear_error(&ge);
		hc_url_clean(url);
		return result;
	}

	hc_url_clean(url);

	/* TODO : update chunk xattr */

	return NULL;
}

gs_error_t*
hc_set_container_versioning(gs_container_t *container, const char *versioning)
{
	return _hc_set_container_global_property(container,
			GS_CONTAINER_PROPERTY_VERSIONING, versioning, TRUE);
}

gs_error_t*
hc_del_container_versioning(gs_container_t *container)
{
	return _hc_set_container_global_property(container, 
            GS_CONTAINER_PROPERTY_VERSIONING, NULL, TRUE);
}

gs_error_t*
hc_set_container_quota(gs_container_t *container, const char *quota)
{
	return _hc_set_container_global_property(container,
			GS_CONTAINER_PROPERTY_QUOTA, quota, TRUE);
}

gs_container_t*
hc_resolve_meta2_entry(gs_grid_storage_t *gs, const char *container_name,
                int auto_create, gs_error_t **gs_err)
{
	return gs_get_storage_container (gs,container_name, NULL, auto_create,
			gs_err);
}

