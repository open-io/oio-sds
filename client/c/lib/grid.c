/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "./gs_internals.h"
#include "./meta_resolver_explicit.h"
#include "./meta_resolver_metacd.h"

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
			if (log4c_init())
				g_printerr("cannot load log4c\n");
			else if ((file=getenv(ENV_LOG4C_LOAD)))
				log4c_load(file);
		}

		if (NULL != (glib = getenv(ENV_GLIB2_ENABLE))) {
			g_log_set_default_handler(logger_stderr, NULL);
		}
		else {
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

const char*
gs_get_namespace(gs_grid_storage_t *gs)
{
	return !gs ? "(nil)" : gs->ni.name;
}

gs_grid_storage_t*
gs_grid_storage_init_flags(const gchar *ns, uint32_t flags,
		int to_cnx, int to_req, gs_error_t **err)
{
	gs_grid_storage_t *gs=NULL;
	register const gchar *sep;
	
	env_init();
	
	/*parse the arguments*/
	if (!ns || !*ns) {
		GSERRORSET(err,"Invalid parameter");
		return NULL;
	}

	DEBUG("Creating a new GridStorage client for namespace [%s]", ns);

	/*inits a new gs_grid_storage_t*/
	gs = calloc (1, sizeof(gs_grid_storage_t));
	if (!gs)
	{
		GSERRORSET(err,"Memory allocation failure");
		return NULL;
	}

	g_strlcpy(gs->ni.name, ns, LIMIT_LENGTH_NSNAME);
	if (NULL != (sep = strchr(ns, '.'))) {
		gs->physical_namespace = g_strndup(ns, sep-ns);
		gs->virtual_namespace = g_strdup(sep+1);
	}
	else {
		gs->physical_namespace = g_strdup(ns);
		gs->virtual_namespace = NULL;
	}

	if (!(flags & GSCLIENT_NOINIT)) {
		GError *gErr = NULL;

		gs->metacd_resolver = resolver_metacd_create (ns, &gErr);
		if (!gs->metacd_resolver) {
			GSERRORCAUSE(err,gErr,"Cannot init the metacd");
			if (gErr) g_clear_error(&gErr);
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
			GSETERROR(&e, "Too many update attempts");
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
gs_resolve_meta1v2 (gs_grid_storage_t *gs, const container_id_t cID,
		int read_only, GSList *exclude, GError **err)
{
	int attempts=NB_ATTEMPTS_RESOLVE_M1;
	GError *gErr=NULL;

	addr_info_t* _try (void)
	{
		addr_info_t *pA=NULL;

		if ((attempts--)<=0) {
			GSETERROR(&gErr,"too many attempts");
			return NULL;
		}

		/* tries a metacd resolution, and if it succeeds, clears the direct resolver */
		if (resolver_metacd_is_up (gs->metacd_resolver)) {
			pA = resolver_metacd_get_meta1 (gs->metacd_resolver, cID, read_only, exclude, &gErr);
			if (pA) {
				resolver_direct_clear (gs->direct_resolver);
				return pA;
			}
			DEBUG("METACD error: META1 resolution failure. cause:\r\n\t%s",(gErr?gErr->message:"?"));
		}

		pA = resolver_direct_get_meta1 (gs->direct_resolver, cID, read_only, exclude, &gErr);
		if (!pA)
			return _try();
		return pA;
	}

	addr_info_t *resAddr = _try();
	if (!resAddr && err) {
		*err = gErr;
	} else {
		if (gErr)
			g_error_free(gErr);
	}
	return resAddr;
}

addr_info_t* gs_resolve_meta1 (gs_grid_storage_t *gs,
	container_id_t cID, GError **err)
{
	return gs_resolve_meta1v2(gs, cID, 0, NULL, err);
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
		pL = resolver_direct_get_meta2_once (gs->direct_resolver, gs->ni.name, cID, exclude, &gErr);

		if (pL)
			return pL;

		if (gErr) {
			if (gErr->code==CODE_CONTAINER_NOTFOUND) {
				/*in this case, no need to retry*/
				return NULL;
			} else if (CODE_REFRESH_META0(gErr->code) || gErr->code < 100 || gErr->code == 500) {
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
_fill_meta1_tabs(char ***p_m1_url_tab, addr_info_t **p_addr_tab, gs_grid_storage_t *gs, container_id_t cid)
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
	while (NULL != (addr = gs_resolve_meta1v2(gs, cid, 0, meta1_list, NULL)))
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

	_fill_meta1_tabs(&(location->m1_url), NULL, container->info.gs, C0_ID(container));

	return location;
}

struct gs_container_location_s *
gs_locate_container_by_hexid(gs_grid_storage_t *gs, const char *hexid, gs_error_t **gserr)
{
	addr_info_t *addr;
	container_id_t cid;
	addr_info_t *m1_addr;
	gchar str_addr[STRLEN_ADDRINFO];
	struct gs_container_location_s *location;

	location = calloc(1, sizeof(*location));
	if (!location) {
		GSERRORSET(gserr, "Memory allocation failure");
		return NULL;
	}
	
	container_id_hex2bin(hexid, strlen(hexid), &cid, NULL);
	location->container_hexid = strdup(hexid);
	
	/*resolve meta0*/
	addr_info_to_string(&(gs->direct_resolver->meta0), str_addr, sizeof(str_addr));
	location->m0_url = strdup(str_addr);

	_fill_meta1_tabs(&(location->m1_url), &m1_addr, gs, cid);

	/* In this case we ask the META1 for the raw container */
	do {
		struct metacnx_ctx_s cnx_tmp;
		struct meta1_raw_container_s *m1_raw;
		GError *gerror_local;

		gerror_local = NULL;
		memset(&cnx_tmp, 0x00, sizeof(cnx_tmp));
		cnx_tmp.fd = -1;
		memcpy(&(cnx_tmp.addr), &(m1_addr[0]), sizeof(addr_info_t));
		m1_raw = meta1_remote_get_container_by_id(&cnx_tmp, cid, &gerror_local,
			gs_grid_storage_get_timeout(gs, GS_TO_M1_CNX)/1000, gs_grid_storage_get_timeout(gs, GS_TO_M1_OP)/1000);
		if (!m1_raw) {
			GSERRORCAUSE(gserr, gerror_local, "Container ID=[%s] not found", hexid);
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
		location->container_name = strdup(m1_raw->name);

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
gs_locate_container_by_name(gs_grid_storage_t *gs, const char *name, gs_error_t **gserr)
{
	container_id_t cid;
	addr_info_t *addr;
	GSList *m2_list;
	gchar str_addr[STRLEN_ADDRINFO], str_cid[STRLEN_CONTAINERID];
	struct gs_container_location_s *location;
	GError *err;

	bzero(str_cid, sizeof(str_cid));
	bzero(str_addr, sizeof(str_addr));

	location = calloc(1, sizeof(*location));
	if (!location) {
		GSERRORSET(gserr, "Memory allocation failure");
		return NULL;
	}
	
	meta1_name2hash(cid, gs->ni.name, name);
	container_id_to_string(cid, str_cid, sizeof(str_cid));

	location->container_name = strdup(name);
	location->container_hexid = strdup(str_cid);
	
	/*resolve meta0*/
	addr_info_to_string(&(gs->direct_resolver->meta0), str_addr, sizeof(str_addr));
	location->m0_url = strdup(str_addr);
	
	/*resolve meta2*/
	m2_list = gs_resolve_meta2(gs, cid, &err);
	if (m2_list) {
		char *str_addr_copy;
		guint i, length;
		GSList *m2;

		length = g_slist_length(m2_list);
		location->m2_url = calloc(length+1, sizeof(char*));
		for (i=0, m2=m2_list; m2 ;m2=m2->next) {
			if (NULL != (addr = m2->data) && addr->port != 0) {
				addr_info_to_string(addr, str_addr, sizeof(str_addr));
				if (NULL != (str_addr_copy = strdup(str_addr)))
					location->m2_url[i++] = str_addr_copy;
			}
		}

		g_slist_foreach(m2_list, addr_info_gclean, NULL);
		g_slist_free(m2_list);

		_fill_meta1_tabs(&(location->m1_url), NULL, gs, cid);
	} else {
		if (err) {
			GSERRORCAUSE(gserr, err, "Error resolving meta2");
			g_error_free(err);
		}
	}

	return location;
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

