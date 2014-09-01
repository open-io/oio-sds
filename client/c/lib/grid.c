#include "./gs_internals.h"

long unsigned int wait_on_add_failed = 1000LU;

static void
env_init (void)
{
	static volatile int init_done = 0;
	char *enabled=NULL, *file=NULL, *str;
	char *glib=NULL;

	if (!init_done) {

		init_done = 1;

		if (!g_thread_supported ())
			g_thread_init (NULL);

		/* Enables log4c logging */
		if (NULL != (enabled = getenv(ENV_LOG4C_ENABLE))) {
			if (enabled[0] != '0') { // I mean '0', not '\0'
				if (log4c_init())
					g_printerr("cannot load log4c\n");
				else if ((file=getenv(ENV_LOG4C_LOAD)))
					log4c_load(file);
			}
		}

		if (NULL != (glib = getenv(ENV_GLIB2_ENABLE))) {
			g_log_set_default_handler(logger_stderr, NULL);
		}
		else if (!enabled) {
			g_log_set_default_handler(logger_noop, NULL);
		}

		/*configure the sleep time between two failed ADD actions*/
		wait_on_add_failed = 10000UL;
		if ((str = getenv(ENV_WAIT_ON_FAILED_ADD))) {
			gint64 i64 = g_ascii_strtoll( str, NULL, 10 );
			if (i64>=0LL && i64<=10000LL)
				wait_on_add_failed = i64;
		}
	}
}

int
gs_set_namespace(gs_grid_storage_t *gs, const char *vns)
{
	if (!gs)
		return 0;

	if (vns && !g_str_has_prefix(vns, gs->ni.name))
		return 0;

	if (gs->full_vns)
		g_free(gs->full_vns);

	gs->full_vns = vns ? g_strdup(vns) : NULL;
	return 1;
}

const char*
gs_get_namespace(gs_grid_storage_t *gs)
{
	return !gs ? "(nil)" : gs->physical_namespace;
}

const char*
gs_get_virtual_namespace(gs_grid_storage_t *gs)
{
	if (!gs)
		return NULL;
	char *s = strchr(gs->full_vns, '.');
	return (s!=NULL) ? s+1 : NULL;
}

const char*
gs_get_full_vns(gs_grid_storage_t *gs)
{
	return !gs ? "(nil)" : gs->full_vns?
			gs->full_vns : gs->physical_namespace;
}

gs_grid_storage_t*
gs_grid_storage_init_flags(const gchar *ns, uint32_t flags,
		int to_cnx, int to_req, gs_error_t **err)
{
	gs_grid_storage_t *gs=NULL;
	register const gchar *sep;
	namespace_info_t *ni;

	env_init();

	/*parse the arguments*/
	if (!ns || !*ns) {
		GSERRORSET(err,"Invalid parameter");
		return NULL;
	}

	DEBUG("Creating a new GridStorage client for namespace [%s]", ns);

	/*inits a new gs_grid_storage_t*/
	gs = calloc (1, sizeof(gs_grid_storage_t));
	if (!gs) {
		GSERRORSET(err,"Memory allocation failure");
		return NULL;
	}

	if (!(flags & GSCLIENT_NOINIT)) {
		GError *gErr = NULL;
		ni = get_namespace_info(ns, &gErr);
		if (!ni) {
			GSERRORCAUSE(err,gErr,"Cannot get namespace info");
			if (gErr)
				g_clear_error(&gErr);
			free(gs);
			return NULL;
		}
		namespace_info_copy(ni, &(gs->ni), &gErr);
		namespace_info_free(ni);
		if (gErr != NULL) {
			GSERRORCAUSE(err, gErr, "Failed to copy namespace info");
			g_clear_error(&gErr);
			free(gs);
			return NULL;
		}
	}

	if (NULL != (sep = strchr(ns, '.'))) {
		gs->physical_namespace = g_strndup(ns, sep-ns);
	}
	else {
		gs->physical_namespace = g_strdup(ns);
	}
	gs->full_vns = g_strdup(ns);

	if (!(flags & GSCLIENT_NOINIT)) {
		GError *gErr = NULL;
		gs->metacd_resolver = resolver_metacd_create (ns, &gErr);
		if (!gs->metacd_resolver) {
			GSERRORCAUSE(err,gErr,"Cannot init the metacd");
			if (gErr)
				g_clear_error(&gErr);
			free(gs);
			return NULL;
		}

		gs->direct_resolver = resolver_direct_create_with_metacd (ns,
				gs->metacd_resolver, to_cnx, to_req, &gErr);
		if (!gs->direct_resolver) {
			GSERRORCAUSE(err,gErr,"Cannot init the direct resolver");
			if (gErr)
				g_clear_error(&gErr);
			resolver_metacd_free(gs->metacd_resolver);
			free(gs);
			return NULL;
		}
	}

	gs->timeout.rawx.op =  RAWX_TOREQ_DEFAULT;
	gs->timeout.rawx.cnx = RAWX_TOCNX_DEFAULT;
	gs->timeout.m2.op =   M2_TOREQ_DEFAULT;
	gs->timeout.m2.cnx =  M2_TOCNX_DEFAULT;
	g_strlcpy(gs->ni.name, ns, sizeof(gs->ni.name));

	if (NULL != strchr(gs->ni.name, '.'))
		* (strchr(gs->ni.name, '.')) = '\0';

	return gs;
}

gs_grid_storage_t*
gs_grid_storage_init2(const gchar *ns, int to_cnx, int to_req,
		gs_error_t **err)
{
	return gs_grid_storage_init_flags(ns, 0, to_cnx, to_req, err);
}

gs_grid_storage_t* gs_grid_storage_init (const gchar *ns,
	gs_error_t **err)
{
	return gs_grid_storage_init_flags(ns, 0,
			CS_TOCNX_DEFAULT, CS_TOREQ_DEFAULT, err);
}

int
gs_update_meta1_master (gs_grid_storage_t *gs, const container_id_t cID,
		const char *m1)
{
	int attempts = NB_ATTEMPTS_UPDATE_M1;

	int _try (void)
	{
		GError *e = NULL;

		if ((attempts--) <= 0) {
			//leak memory, e not free
			return 0;
		}

		/* tries a metacd resolution, and if it succeeds, clears the direct resolver */
		if (resolver_metacd_is_up (gs->metacd_resolver)) {
			if(resolver_metacd_set_meta1_master (gs->metacd_resolver, cID, m1, &e)) {
				resolver_direct_clear (gs->direct_resolver);
				return 1;
			}
			DEBUG("METACD error: META1 update failure. cause:\r\n\t%s",(e ? e->message : "?"));
			if(NULL != e)
				g_clear_error(&e);
		}

		if(!resolver_direct_set_meta1_master (gs->direct_resolver, cID, m1, &e))
			DEBUG("META1 update failure. cause:\r\n\t%s",(e ? e->message : "?"));
			if(NULL != e)
				g_clear_error(&e);
			return _try();
		return 1;
	}

	return _try();
}

addr_info_t*
gs_resolve_meta1v2_v2(gs_grid_storage_t *gs, const container_id_t cID,
		const gchar *cname, int read_only, GSList *exclude,
		gboolean has_before_create, GError **err)
{
	gchar str_cid[STRLEN_CONTAINERID+1];
	int attempts=NB_ATTEMPTS_RESOLVE_M1;
	GError *gErr=NULL;
	gboolean ref_exists = FALSE, metacd_is_up = FALSE;

	addr_info_t* _try (void)
	{
		addr_info_t *pA=NULL;

		if ((attempts--)<=0) {
			GSETERROR(&gErr,"too many attempts");
			return NULL;
		}

		/* tries a metacd resolution, and if it succeeds, clears the direct resolver */
		metacd_is_up = resolver_metacd_is_up (gs->metacd_resolver);
		if (metacd_is_up) {
			pA = resolver_metacd_get_meta1 (gs->metacd_resolver, cID, read_only, exclude, &ref_exists, NULL);
			if (pA) {
				resolver_direct_clear (gs->direct_resolver);
			} else {
				DEBUG("METACD error: META1 resolution failure. cause:\r\n\t%s",(gErr?gErr->message:"?"));
			}
		}

		if (NULL == pA) {
			pA = resolver_direct_get_meta1 (gs->direct_resolver, cID, read_only, exclude, &gErr);
			if (!pA)
				return _try();
		}

		if (NULL == cname)
			return pA;

		if (!ref_exists || !metacd_is_up) {
			if (has_before_create) {
				if (meta1v2_remote_has_reference(pA, &gErr, gs_get_full_vns(gs),
						cID, gs_grid_storage_get_timeout(gs, GS_TO_M1_CNX),
						gs_grid_storage_get_timeout(gs, GS_TO_M1_OP))) {
					DEBUG("METACD reference already exists in meta1: [%s/%s]",
							cname, str_cid);
					return pA;
				} else if (gErr && gErr->code == CODE_CONTAINER_NOTFOUND) {
					g_clear_error(&gErr);
				} else {
					ERROR("METACD error checking reference [%s] in meta1: %s",
							str_cid, (gErr?gErr->message:"?"));
					g_clear_error(&gErr);
				}
				DEBUG("Creating reference in meta1: [%s/%s]", cname, str_cid);
			}
			if (meta1v2_remote_create_reference(pA, &gErr, gs_get_full_vns(gs),
					cID, cname,
					gs_grid_storage_get_timeout(gs, GS_TO_M1_CNX),
					gs_grid_storage_get_timeout(gs, GS_TO_M1_OP),
					NULL)) {
				DEBUG("METACD created reference in meta1: [%s/%s]",
						cname, str_cid);
			} else {
				if (gErr && gErr->code == CODE_CONTAINER_EXISTS) {
					DEBUG("METACD reference already exists in meta1: [%s/%s]",
							cname, str_cid);
				} else {
					ERROR("METACD error creating reference [%s] in meta1: %s",
							str_cid, (gErr?gErr->message:"?"));
					if (metacd_is_up)
						resolver_metacd_decache(gs->metacd_resolver, cID);
					GSETERROR(&gErr,"Could not create reference");
					exclude = g_slist_prepend(exclude, pA);
					/* if (err) *err = gErr; */
					return _try();
				}
			}
		}

		return pA;
	}

	memset(str_cid, 0, sizeof(str_cid));
	container_id_to_string(cID, str_cid, sizeof(str_cid)-1);

	addr_info_t *resAddr = _try();
	if (!resAddr && err) {
		*err = gErr;
	} else {
		if (gErr)
			g_error_free(gErr);
	}
	return resAddr;
}

addr_info_t*
gs_resolve_meta1v2 (gs_grid_storage_t *gs, const container_id_t cID, const gchar *cname,
		int read_only, GSList *exclude, GError **err)
{
	return gs_resolve_meta1v2_v2(gs, cID, cname, read_only, exclude, FALSE, err);
}

addr_info_t* gs_resolve_meta1 (gs_grid_storage_t *gs,
	container_id_t cID, GError **err)
{
	return gs_resolve_meta1v2(gs, cID, NULL, 0, NULL, err);
}

GSList* gs_resolve_meta2 (gs_grid_storage_t *gs,
	container_id_t cID, GError **err)
{
	int attempts=NB_ATTEMPTS_RESOLVE_M2;
	GError *gErr=NULL;
	GSList *m1_exclude = NULL;

	GSList* _try (GSList **exclude)
	{
		GSList *pL=NULL;

		if ((attempts--)<=0) {
			GSETERROR(&gErr,"too many attempts");
			return NULL;
		}

		/* tries a metacd resolution, and if it succeeds, clears the
		 * direct resolver */
		if (resolver_metacd_is_up (gs->metacd_resolver)) {
			pL = resolver_metacd_get_meta2 (gs->metacd_resolver, cID, &gErr);
			if (pL) {
				resolver_direct_clear (gs->direct_resolver);
				return pL;
			} else if (gErr && gErr->code==CODE_CONTAINER_NOTFOUND) {
				return NULL;
			}

			if (!gErr)
				GSETERROR(&gErr,"METACD Resolution error");
		}

		/* between two meta2 direct resolutions, we want to
		 * be sure a metacd has not been spawned, so only
		 * one try is made this turn */
		pL = resolver_direct_get_meta2_once (gs->direct_resolver,
				gs_get_full_vns(gs), cID, exclude, &gErr);

		if (pL)
			return pL;

		if (gErr) {
			if (gErr->code==CODE_CONTAINER_NOTFOUND) {
				/*in this case, no need to retry*/
				return NULL;
			} else if (CODE_REFRESH_META0(gErr->code) ||
					gErr->code < 100 || gErr->code == 500) {
				gs_decache_all( gs);
				return _try(exclude);
			}
		} else GSETERROR(&gErr,"Unknown error, not retrying a direct resolution");

		return NULL;
	}

	GSList *resList = _try(&m1_exclude);
	if (!resList) {
		if (err)
			*err = gErr;
		else if (gErr) {
			g_error_free( gErr );
		}
	}

	if(NULL != m1_exclude) {
		g_slist_foreach(m1_exclude, addr_info_gclean, NULL);
		g_slist_free(m1_exclude);
	}

	return resList;
}


void gs_decache_container (gs_grid_storage_t *gs, container_id_t cID)
{
	if (!gs || !cID) {
		ALERT("invalid parameter");
		return;
	}
	
	if (resolver_metacd_is_up (gs->metacd_resolver)) {
		/*resolver_direct_clear (gs->direct_resolver);*/
		resolver_metacd_decache (gs->metacd_resolver, cID);
	}
}

void gs_decache_all (gs_grid_storage_t *gs)
{
	if (!gs) {
		ALERT("invalid parameter");
		return;
	}
	
	if (resolver_metacd_is_up (gs->metacd_resolver))
		resolver_metacd_decache_all (gs->metacd_resolver);
	else
		resolver_direct_decache_all (gs->direct_resolver);
}

static void
_fill_meta1_tabs(char ***p_m1_url_tab, addr_info_t **p_addr_tab, gs_grid_storage_t *gs,
		container_id_t cid, gchar *cname)
{
	addr_info_t *addr;
	gchar str_addr[STRLEN_ADDRINFO];
	GSList *meta1_list = NULL;
	GSList *iter_list = NULL;
	char **m1_tab = NULL;
	addr_info_t *addr_tab = NULL;
	guint i, length;

	// The meta1_list will contain all meta1 addresses.
	// It is passed as the 'exclude' argument to gs_resolve_meta1v2.
	while (NULL != (addr = gs_resolve_meta1v2(gs, cid, cname, 0, meta1_list, NULL)))
		meta1_list = g_slist_append(meta1_list, addr);
	
	// The result tabs will contain all addresses, plus a NULL trailing element.
	length = g_slist_length(meta1_list) + 1;

	// Result tabs creation.
	if (p_m1_url_tab)
		m1_tab = calloc(length, sizeof(char*));
	if (p_addr_tab)
		addr_tab = calloc(length, sizeof(addr_info_t));
	
	// Fill result tabs
	for (i = 0, iter_list = meta1_list; iter_list; iter_list=iter_list->next, i++) {
		addr_info_to_string(iter_list->data, str_addr, sizeof(str_addr));
		if (p_m1_url_tab)
			m1_tab[i] = strdup(str_addr);
		if (p_addr_tab)
			memcpy(addr_tab + i, iter_list->data, sizeof(addr_info_t));
	}

	// Cleanup
	if (meta1_list) {
		iter_list = meta1_list;
		do {
			g_free(iter_list->data);
		} while (NULL != (iter_list = iter_list->next));
		g_slist_free(meta1_list);
	}

	// Set results
	if (p_m1_url_tab)
		*p_m1_url_tab = m1_tab;
	if (p_addr_tab)
		*p_addr_tab = addr_tab;
}

struct gs_container_location_s *
gs_locate_container(gs_container_t *container, gs_error_t **gserr)
{
	GSList *m2_list;
	gchar str_addr[STRLEN_ADDRINFO];
	struct gs_container_location_s *location;

	location = calloc(1, sizeof(*location));
	if (!location) {
		GSERRORSET(gserr, "Memory allocation failure");
		return NULL;
	}

	/* the names are already known*/
	location->container_name = strdup(C0_NAME(container));
	location->container_hexid = strdup(C0_IDSTR(container));
	
	/*resolve meta0*/
	addr_info_to_string(&(container->info.gs->direct_resolver->meta0), str_addr, sizeof(str_addr));
	location->m0_url = strdup(str_addr);
	
	/*resolve meta2*/
	m2_list = gs_resolve_meta2(container->info.gs, C0_ID(container), NULL);
	if (m2_list) {
		addr_info_t *addr;
		GSList *m2;
		guint i, length;

		length = g_slist_length(m2_list);
		location->m2_url = calloc(length+1, sizeof(char*));
		for (i=0, m2=m2_list; m2 ;m2=m2->next) {
			addr = m2->data;
			if (addr) {
				addr_info_to_string(addr, str_addr, sizeof(str_addr));
				location->m2_url[i++] = strdup(str_addr);
			}
		}

		g_slist_foreach(m2_list, addr_info_gclean, NULL);
		g_slist_free(m2_list);
	}

	_fill_meta1_tabs(&(location->m1_url), NULL, container->info.gs, C0_ID(container), C0_NAME(container));

	return location;
}

static struct gs_container_location_s *
_gs_locate_container_by_cid(gs_grid_storage_t *gs, container_id_t cid, char** out_nsname_on_m1, 
	gs_error_t **gserr)
{
	addr_info_t *addr;
	addr_info_t *m1_addr;
	gchar str_addr[STRLEN_ADDRINFO], str_cid[STRLEN_CONTAINERID];;
	struct gs_container_location_s *location;

	location = calloc(1, sizeof(*location));
	if (!location) {
		GSERRORSET(gserr, "Memory allocation failure");
		return NULL;
	}
	
	container_id_to_string(cid, str_cid, sizeof(str_cid));
	location->container_hexid = strdup(str_cid);
	
	/*resolve meta0*/
	addr_info_to_string(&(gs->direct_resolver->meta0), str_addr, sizeof(str_addr));
	location->m0_url = strdup(str_addr);

	_fill_meta1_tabs(&(location->m1_url), &m1_addr, gs, cid, NULL);

	/* In this case we ask the META1 for the raw container */
	do {
		struct metacnx_ctx_s cnx_tmp;
		struct meta1_raw_container_s *m1_raw;
		GError *gerror_local;
		gchar *cname = NULL;

		gerror_local = NULL;
		memset(&cnx_tmp, 0x00, sizeof(cnx_tmp));
		cnx_tmp.fd = -1;
		memcpy(&(cnx_tmp.addr), &(m1_addr[0]), sizeof(addr_info_t));
		m1_raw = meta1_remote_get_container_by_id(&cnx_tmp, cid, &gerror_local,
			gs_grid_storage_get_timeout(gs, GS_TO_M1_CNX)/1000, gs_grid_storage_get_timeout(gs, GS_TO_M1_OP)/1000);
		if (!m1_raw) {
			GSERRORCAUSE(gserr, gerror_local, "Container ID=[%s] not found", str_cid);
			g_clear_error(&gerror_local);
			gs_container_location_free(location);
			if (m1_addr)
				free(m1_addr);
			return NULL;
		}

		/* copy the ADDRESSES of the possible META2 */
		if (m1_raw->meta2) {
			char *str_addr_copy;
			guint i, length;
			GSList *m2;

			length = g_slist_length(m1_raw->meta2);
			location->m2_url = calloc(length+1, sizeof(char*));
			for (i=0,m2=m1_raw->meta2; m2 ;m2=m2->next) {
				if (NULL != (addr = m2->data) && addr->port != 0) {
					addr_info_to_string(addr, str_addr, sizeof(str_addr));
					if (NULL != (str_addr_copy = strdup(str_addr)))
						location->m2_url[i++] = str_addr_copy;
				}
			}
			g_slist_foreach(m1_raw->meta2, addr_info_gclean, NULL);
			g_slist_free(m1_raw->meta2);
		}
		
		/* copy the container's name */
		// the answer is formatted NS/CNAME, so we need to skip NS/
		cname = strchr(m1_raw->name, '/');		
		if (cname) {
			location->container_name = g_strdup(cname + 1);
			if (out_nsname_on_m1) {
				cname[0] = '\0';
				*out_nsname_on_m1 = g_strdup(m1_raw->name);    // used if ns is a VNS
			}
		}

		/* that's all, folks! */
		if (m1_addr)
			free(m1_addr);
		g_free(m1_raw);
		if (gerror_local)
			g_error_free(gerror_local);
	} while (0);

	return location;
}


struct gs_container_location_s *
gs_locate_container_by_hexid(gs_grid_storage_t *gs, const char *hexid, gs_error_t **gserr)
{
	return gs_locate_container_by_hexid_v2(gs, hexid, NULL, gserr);
}


struct gs_container_location_s *
gs_locate_container_by_hexid_v2(gs_grid_storage_t *gs, const char *hexid, char** out_nsname_on_m1,
                              gs_error_t **gserr)
{
    container_id_t cid;

    if (hexid == NULL) {
        GSERRORSET(gserr, "No container id provided");
        return NULL;
    }

	container_id_hex2bin(hexid, strlen(hexid), &cid, NULL);

    return _gs_locate_container_by_cid(gs, cid, out_nsname_on_m1, gserr);
}



struct gs_container_location_s *
gs_locate_container_by_name(gs_grid_storage_t *gs, const char *name, gs_error_t **gserr)

{
	container_id_t cid;

	if (name == NULL) {
		GSERRORSET(gserr, "No container name provided");
		return NULL;
	}
	
	meta1_name2hash(cid, gs_get_full_vns(gs), name);

	return _gs_locate_container_by_cid(gs, cid, NULL, gserr);
}

void
gs_container_location_free(struct gs_container_location_s *location)
{
	char ** ptr;
	
	if (!location)
		return;
	if (location->m0_url)
		free(location->m0_url);
	if (location->m1_url) {
		for (ptr=location->m1_url; *ptr; ptr++)
			free(*ptr);
		free(location->m1_url);
	}
	if (location->m2_url) {
		for (ptr=location->m2_url; *ptr; ptr++)
			free(*ptr);
		free(location->m2_url);
	}
	if (location->container_hexid)
		free(location->container_hexid);
	if (location->container_name)
		free(location->container_name);
	memset(location, 0x00, sizeof(*location));
	free(location);
}

