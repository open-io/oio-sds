#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.client.resolv.local"
#endif

#include "./gs_internals.h"

static void
_clean_cache_entry(gpointer data, gpointer udata)
{
	(void) udata;
	if (data)
		g_strfreev((gchar**)data);
}

void resolver_direct_clear (resolver_direct_t *r)
{
	if (!r)
		return;

	M0CACHE_LOCK(*r);
	if (r->refresh_pending)
	{
		DEBUG("META0 cache not cleared, a refresh is running");
	}
	else if (r->mappings)
	{
		g_ptr_array_foreach (r->mappings, _clean_cache_entry, NULL);
		g_ptr_array_free (r->mappings, TRUE);
		r->mappings = NULL;
		DEBUG("META0 cache cleared");
	}
	M0CACHE_UNLOCK(*r);
}


static
GPtrArray*
build_meta0_cache (struct resolver_direct_s *r, GError **err)
{
	GSList *m0_list=NULL;
	GPtrArray *array=NULL;

	/*now call the meta0 reference*/
	if (!(m0_list = meta0_remote_get_meta1_all (&(r->meta0), r->timeout.m0.op, err)))
	{
		gchar str_addr[128];
		memset(str_addr, 0x00, sizeof(str_addr));
		addr_info_to_string(&(r->meta0), str_addr, sizeof(str_addr));
		GSETERROR (err,"META0 error : Cannot get the reference from %s", str_addr);
		WARN ("Cannot get the META0 reference from %s", str_addr);
		return NULL;
	}

	array = meta0_utils_list_to_array(m0_list); 

	g_slist_foreach (m0_list, meta0_info_gclean, NULL);
	g_slist_free (m0_list);

	return array;
}


static
int
UNSAFE_resolver_direct_reload (struct resolver_direct_s *r, gboolean locked, GError **err)
{
	int rc = 0;

	DEBUG("META0 cache reload wanted");
	gscstat_tags_start(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);
	/*sanity checks*/
	if (!r)
	{
		GSETERROR(err, "invalid parameter");
		goto exit_label;
	}

	/*start a critical section to access the state of the resolver*/
	if (!locked)
		M0CACHE_LOCK(*r);
	
	if (r->refresh_pending)
	{
		GTimeVal gtv;
		
		DEBUG("META0 cache already being refreshed");

		g_get_current_time (&gtv);
		g_time_val_add (&gtv, COND_MAXWAIT_MS * 1000);

		if (g_cond_timed_wait(r->refresh_condition, r->use_mutex, &gtv)) {
			/*when signal is thrown, and g_condwait return, mutex is locked*/
			if (!locked) M0CACHE_UNLOCK(*r);
			rc = 1;
		} else {
			/*timeout*/
			if (!locked) M0CACHE_UNLOCK(*r);
			GSETERROR(err,"timeout on a pending refresh");
			rc = 0;
		}
	}
	else
	{
		GPtrArray *newMappings=NULL;
		
		/*mark the resolver as being refreshed and leave the critical section*/
		r->refresh_pending = TRUE;

		if (!locked)
			M0CACHE_UNLOCK(*r);

		/*contact meta0 and build a reference */
		newMappings = build_meta0_cache (r, err);
		
		if (!locked)
			M0CACHE_LOCK(*r);
		
		if (!newMappings) {
			/*refresh error*/
			ERROR("Cannot refresh the META0 cache");
			rc=0;
		} else {
			if ( r->mappings )
			{
				g_ptr_array_foreach (r->mappings, _clean_cache_entry, NULL);
				g_ptr_array_free (r->mappings, TRUE);
				r->mappings = NULL;
			}
			r->mappings = newMappings;
			DEBUG("META0 cache has been refreshed");
			rc=1;
		}

		/* refresh done, change the state in a critical section and wake up
		 * all the threads waiting on the condition. */
		r->refresh_pending = FALSE;	
		g_cond_broadcast (r->refresh_condition);
		
		if (!locked)
			M0CACHE_UNLOCK(*r);
	}

exit_label:	

	gscstat_tags_end(GSCSTAT_SERVICE_META0, GSCSTAT_TAGS_REQPROCTIME);
	return rc;

}


void
resolver_direct_decache_all (resolver_direct_t *r)
{
	GError *gErr=NULL;

	if (!r)
	{
		ERROR("Invalid parameter");
		return;
	}

	if (!UNSAFE_resolver_direct_reload (r, 0, &gErr))
	{
		ERROR("Cannot decache");
		WARN("Cause:%s", g_error_get_message(gErr));
	}
}


static gboolean
_is_usable_meta1(addr_info_t *addr, GSList *exclude) {
	GSList *l = NULL;
	for (l = exclude; l && l->data; l=l->next) {
		if(addr_info_equal(l->data, addr))
			return FALSE;
	}
	return TRUE;
}

addr_info_t*
resolver_direct_get_meta1 (resolver_direct_t *r, const container_id_t cID, int ro, GSList *exclude, GError **err)
{
	guint16 i;
        addr_info_t *pA = NULL;

        if (!r || !cID) {
                GSETERROR (err, "invalid parameter");
                return NULL;
        }

        memcpy(&i, cID, 2);
        i = GUINT16_FROM_LE(i);

        /**/
        M0CACHE_LOCK(*r);
        if (!r->mappings)
        {
                TRACE("No META0 cache, trying a reload");
                if (!UNSAFE_resolver_direct_reload(r, 1, err))
                {
                        M0CACHE_UNLOCK(*r);
                        GSETERROR(err, "Cannot load the local META0 cache");
                        return NULL;
                }
        }
	gchar ** meta1_addresses = NULL;
	gchar *addr_str = NULL;
	meta1_addresses = r->mappings->pdata[i];

	if(!meta1_addresses) {
		GSETERROR(err, "entry not found");
		goto end_label;
	}

	guint nb_meta1 = g_strv_length(meta1_addresses);
	guint tmp = rand()%nb_meta1;
	guint try = 0;
	if(g_slist_length(exclude) == nb_meta1) {
		goto end_label;
	}


	while(try < nb_meta1) {
		if(!ro) {
			/* take the first */
			addr_str = meta1_addresses[try];
		} else {
			/* take random */
			tmp = ((tmp+1) % nb_meta1);
			addr_str = meta1_addresses[tmp];
		}
		gchar **token = g_strsplit(addr_str, ":", 2);
		if(g_strv_length(token) != 2) {
			GSETERROR(err, "Cannot parse cache entry");
			g_strfreev(token);
			goto end_label;
		}
		pA = build_addr_info(token[0], atoi(token[1]),err);
		g_strfreev(token);
		if ( _is_usable_meta1(pA, exclude))
			break;
		g_free(pA);
		pA = NULL;
		try++;
	}
	
end_label:

        M0CACHE_UNLOCK(*r);

        return pA;
}

int
resolver_direct_set_meta1_master (resolver_direct_t *r, const container_id_t cid, const char *master, GError **e)
{
	guint16 i;
	gchar **all = NULL;

        if (!r || !cid || !master) {
                GSETERROR (e, "Invalid parameter");
                return 0;
        }

        memcpy(&i, cid, 2);
        i = GUINT16_FROM_LE(i);

        /**/
        M0CACHE_LOCK(*r);
        if (!r->mappings)
        {
                TRACE("No META0 cache, trying a reload");
                if (!UNSAFE_resolver_direct_reload(r, 1, e))
                {
                        M0CACHE_UNLOCK(*r);
                        GSETERROR(e, "Cannot load the local META0 cache");
                        return 0;
                }
        }
	all = r->mappings->pdata[i];
	if(!all) {
		M0CACHE_UNLOCK(*r);
		GSETERROR(e, "Entry not found");
		return 0;
	}
	guint count = g_strv_length(all);
	if(count < 2) {
		M0CACHE_UNLOCK(*r);
		GSETERROR(e, "Invalid meta0 entry");
		return 0;
	}

	for(uint j = 0; j < count; j++) {
		if(!g_ascii_strcasecmp(master, all[j])) {
			if(j == 0) {
				/* nothing to do, master already in first place */
				break;
			}
			memcpy(all[j], all[0], strlen(all[0]));
			memcpy(all[0], master, strlen(master));
			break;
		}
	}

        M0CACHE_UNLOCK(*r);

        return 1;
}

static GSList *
_service_array_to_slist(char **m2)
{
	GSList *result = NULL;
	addr_info_t *a = NULL;
	for (uint i = 0 ; i < g_strv_length(m2) ; i++) {
		DEBUG("Got meta2=%s", m2[i]);
		a = addr_info_from_service_str(m2[i]);
		if (NULL != a) {
			result = g_slist_prepend(result, a);
			a = NULL;
		}
	}
	return result;
}

GSList *
resolver_direct_get_meta2_once (resolver_direct_t *r, const char *ns, const container_id_t cid,
			GSList **m1_exclude, GError **err)
{
	char **m2 = NULL;
	addr_info_t *m1 = NULL;
	GError *e = NULL;
	GSList *result = NULL;

	if (!r || !cid) {
		GSETERROR(err, "invalid parameter");
		return NULL;
	}

	/*resolves meta1*/
	m1 = resolver_direct_get_meta1 (r, cid, 1, *m1_exclude, &e);
	if (!m1) {
		GSETCODE (err, e ? e->code : 500, "META1 Resolution error : %s", e ? e->message : "no error specified");
		if (NULL != e)
			g_clear_error(&e);
		return NULL;
	}

	/*call META1 to locate the right META2*/
	m2 = meta1v2_remote_list_reference_services (m1, &e, ns, cid, "meta2", (r->timeout.m1.cnx)/1000, (r->timeout.m1.op)/1000);

	DEBUG("Meta2 services listed");


	if (!m2 || 0 == g_strv_length(m2)) {
		if (NULL != e) {
			gchar strm1[50];
			memset(strm1, 0, sizeof(strm1));
			addr_info_to_string(m1, strm1, sizeof(strm1));
			GSETCODE(err, e->code, "Cannot directly resolve META2 : %s [META1=%s]", e->message, strm1);
			if(CODE_CONTAINER_NOTFOUND != e->code) {
				*m1_exclude = g_slist_prepend(*m1_exclude, m1);
			} else {
				g_free(m1);
			}
			g_clear_error(&e);
		} else {
			/* no error, this is simply a container not found */
			GSETCODE(err, CODE_CONTAINER_NOTFOUND, "No service meta2 found for this reference");
			g_free(m1);
		}
		return NULL;
	}

	g_free(m1);
	result = _service_array_to_slist(m2);
	g_strfreev(m2);

	return result;
}


GSList *
resolver_direct_get_meta2 (resolver_direct_t *resolver, const char *ns, const container_id_t cID, GError **e, int max_attempts)
{
	GSList *m1_exclude = NULL;
	GSList *result = NULL;

	GSList* __directly_resolve (resolver_direct_t *r, GSList **exclude, GError **err) {
		GSList *m2 = NULL;

		if (max_attempts-- <= 0) {
			GSETERROR(err, "Too many meta2 resolution attempts");
			return NULL;
		}

		m2 = resolver_direct_get_meta2_once (r, ns, cID, exclude, err);

		if (!m2) {
			if (!err || !(*err)) {
				GSETERROR(err, "Unknown error");
				return NULL;
			} else if ((*err)->code==CODE_CONTAINER_NOTFOUND) {
				INFO("metacd: not found ok");
				return NULL;
			} else if (CODE_REFRESH_META0((*err)->code)) {
				resolver_direct_decache_all (r);
				INFO("metacd: not found fail M0");
				return __directly_resolve (r, exclude, err);
			} else if ((*err)->code < 100 || (*err)->code == 500) {
				INFO("metacd: not found fail code (%d)", (*err)->code);
				return __directly_resolve (r, exclude, err);
			} else {
				return NULL;
			}
		}

		return m2;
	}

	result = __directly_resolve(resolver, &m1_exclude, e);

	if(m1_exclude) {
		g_slist_foreach(m1_exclude, addr_info_gclean, NULL);
		g_slist_free(m1_exclude);
	}

	return result; 
}

void resolver_direct_free (resolver_direct_t *r)
{
	DEBUG("freeing %p", (void*)r);
	
	if (!r)
		return;

	if (r->mappings)
	{
		g_ptr_array_foreach (r->mappings, _clean_cache_entry, NULL);
		g_ptr_array_free (r->mappings, TRUE);
		r->mappings = NULL;
	}

	M0CACHE_FINI_LOCK(*r);
	if (r->refresh_condition)
		g_cond_free (r->refresh_condition);
	free (r);
}


resolver_direct_t*
resolver_direct_create2 (const char * const config, gint to_cnx, gint to_req, GError **err)
{
	return resolver_direct_create_with_metacd(config, NULL, to_cnx, to_req, err);
}

resolver_direct_t*
resolver_direct_create (const char * const config, GError **err)
{
	return resolver_direct_create2(config, CS_TOCNX_DEFAULT, CS_TOREQ_DEFAULT, err);
}

resolver_direct_t*
resolver_direct_create_with_metacd(const gchar * const config, struct metacd_s *metacd, gint to_cnx, gint to_req, GError **err)
{
	resolver_direct_t *r = NULL;

	r = calloc(1, sizeof(resolver_direct_t));
	if (!r) {
		return NULL;
	}

	r->metacd = metacd;
	r->mappings = NULL;
	M0CACHE_INIT_LOCK(*r);
	r->refresh_condition = g_cond_new ();
	r->timeout.conscience.op =  to_req;
	r->timeout.conscience.cnx = to_cnx;
	r->timeout.m0.op =  M0_TOREQ_DEFAULT;
	r->timeout.m0.cnx = M0_TOCNX_DEFAULT;
	r->timeout.m1.op =  M1_TOREQ_DEFAULT;
	r->timeout.m1.cnx = M1_TOCNX_DEFAULT;

	/* Try to resolve the META0 with the metacd */
	if (r->metacd && resolver_metacd_is_up(r->metacd)) {
		GError *err_local = NULL;
		addr_info_t *m0_addr = NULL;

		m0_addr = resolver_metacd_get_meta0(r->metacd, &err_local);
		if (m0_addr) {
			memcpy(&(r->meta0), m0_addr, sizeof(addr_info_t));
			g_free(m0_addr);
			DEBUG("Explicit resolver created for %s (empty), META0 got from the metacd", config);
			return r;
		}
		else {
			DEBUG("META0 resolution failed with metacd : %s",
				((err_local && err_local->message)? err_local->message : "unknown error"));
			if (err_local)
				g_error_free(err_local);
		}
	}

	/* Not found with the metacd, try with the gridagent (through gridcluster) */
	meta0_info_t *meta0_info = NULL;
	meta0_info = get_meta0_info2(config, r->timeout.conscience.cnx, r->timeout.conscience.op, err);
	if (meta0_info) {
		memcpy(&(r->meta0), &(meta0_info->addr), sizeof(addr_info_t));
		g_free(meta0_info);
		DEBUG("Explicit resolver created for %s, META0 got from gridcluster", config);
		return r;
	}

	/* Not found with gridcluster and metacd, then we assume the
	 * config string is the META0 URL */
	gchar *host = NULL;
	gchar *port = NULL;

	/*parse the URL*/
	if (!gs_url_split(config, &host, &port)) {
		GSETERROR(err, "META0 url not recognized '%s'", config);
		free(r);
		return(NULL);
	}

	if (!host || !port) {
		GSETERROR(err, "META0 url badly split '%s'", config);
		if (host)
			g_free(host);
		if (port)
			g_free(port);
		free(r);
		return(NULL);
	}

	/*buils the META0 address*/
	addr_info_t *meta0_addr = build_addr_info (host, atoi(port), err);
	if (!meta0_addr) {
		GSETERROR(err, "Cannot build the META0 address from its URL (host=%s port=%s/%i)",
				host, port, atoi(port));
		g_free(host);
		g_free(port);
		free(r);
		return(NULL);
	}

	memcpy(&(r->meta0), meta0_addr, sizeof(addr_info_t));
	g_free(meta0_addr);
	DEBUG("Explicit resolver created for %s (empty), META0 got from gridcluster", config);
	
	g_free(host);
	g_free(port);
	return r;
}

