#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "hc.tools"
#endif

#include "./gs_internals.h"
#include "./hcadmin.h"

struct global_cpt_s {
	guint64 checkedRef;
	guint64 updatedRef;
	guint64 failedRef;
};

struct thread_user_data_s {
	gchar *ns;
	gchar *type;
	gchar *action;
	gchar *excludesrv;
	gboolean checkonly;
	GMutex *lock;
	GPtrArray *gpa;
	guint indexreach;
	struct global_cpt_s *cpts;
};

	static gs_error_t*
_m1policy_update(gchar *action, gchar *ns,gboolean isprefix, container_id_t cid, gchar *type, gchar *exludesrv, gboolean checkonly, gchar ***result )
{
	GError *err=NULL;
	gs_error_t *hc_error = NULL;
	GSList *exclude = NULL;
	addr_info_t *m1addr;
	gs_grid_storage_t *hc;
	gchar ** hc_result = NULL;

	hc = gs_grid_storage_init(ns, &hc_error);
	if (!hc)
		return hc_error;

	m1addr = gs_resolve_meta1v2(hc,cid,NULL,0,exclude,&err);
	while (m1addr) {
		hc_result = meta1v2_remote_update_m1_policy(m1addr, &err, ns, ( isprefix ? cid : NULL), ( isprefix ? NULL: cid), type, action, checkonly, exludesrv, 300, 300);
		if ( err ) {
			if ( err->code < 100 || err->code > 500 ) {
				exclude=g_slist_prepend(exclude,m1addr);
				m1addr = gs_resolve_meta1v2(hc,cid,NULL,0,exclude,&err);
			} else {
				GRID_WARN("META1 request error (%d) : %s", err->code, err->message);
				GSERRORCAUSE(&hc_error, err, "Failed to apply Meta1 policy\n");
				m1addr=NULL;
			}
			g_clear_error(&err);
		} else {
			break;
		}
	}
	gs_grid_storage_free(hc);
	if(exclude) {
		g_slist_foreach(exclude, addr_info_gclean, NULL);
		g_slist_free(exclude);
	}
	if(m1addr)
		g_free(m1addr);

	*result = hc_result;
	return hc_error;
}


static gs_error_t* _m2_touch(struct hc_url_s *hcurl, guint32 flags)
{
	GError*            err    = NULL;
	gs_error_t*        gserr  = NULL;
	gs_container_t*    cid    = NULL;
	gs_grid_storage_t* hc     = NULL;
	GSList*            m2list = NULL;
	addr_info_t*       m2addr = NULL;
	char str_addr[STRLEN_ADDRINFO] = "";
	const char* ns             = NULL;
	const char* content        = NULL;
	const char* container_name = NULL;

	ns             = hc_url_get(hcurl, HCURL_NS);	
	container_name = hc_url_get(hcurl, HCURL_REFERENCE);
	content        = hc_url_get(hcurl, HCURL_PATH);


	/* init grid client */
	if ((ns==NULL) || (strlen(ns)==0)) {
		GSERRORCODE(&gserr, -1, "Invalid namespace");
		return gserr;
	}
	hc = gs_grid_storage_init(ns, &gserr);
	if (!hc) {
		return gserr;
	}

	/* init container_id */
    if ((container_name==NULL) || (strlen(container_name)==0)) {
        GSERRORCODE(&gserr, -1, "Invalid container_name");
        return gserr;
    }

    cid = gs_init_container(hc, container_name, FALSE, &gserr);
	if (!gserr) {		
		if (!cid) {
			gs_grid_storage_free(hc);
			GSERRORCODE(&gserr, -1, "Invalid container_name %s/%s", ns, container_name);
			return gserr;
		}
	} else return gserr;


	/* search meta2 master */
	m2list = gs_resolve_meta2(hc, C0_ID(cid), &err);		
	if (!m2list) {
        GSERRORCODE(&gserr, -1, "Meta2 Resolution error for NAME=[%s] ID=[%s]", C0_NAME(cid), C0_IDSTR(cid));
		if (cid)
	    	gs_container_free (cid);
		gs_grid_storage_free(hc);
        return gserr;
    }
	m2addr = (addr_info_t*) m2list->data;
	addr_info_to_string (m2addr, str_addr, sizeof(str_addr));

	/* execute touch command */
    if (content && strlen(content)>0) 
		err = m2v2_remote_touch_content(str_addr, NULL, hcurl);
	else 
		err = m2v2_remote_touch_container_ex(str_addr, NULL, hcurl, flags);
	
	/* an error occurs ? */
	if (err) {
		GSERRORCAUSE(&gserr, err, "Failed to execute touch command");
        g_clear_error(&err);
	}

	gs_grid_storage_free(hc);
	if (cid)
    	gs_container_free (cid);
	
	return gserr;
}




static void _pack_result(GPtrArray **gpa,gchar *id,gchar **result,gs_error_t *err, struct global_cpt_s *cpts) {
	if ( !*gpa)
		*gpa = g_ptr_array_new();

	if ( err)
		g_ptr_array_add(*gpa,g_strdup_printf("%s : %s",id,err->msg));
	else {
		gchar **tmp = result;
		for(; tmp && *tmp; tmp++) {
			gchar **tokens = g_strsplit(*tmp,"|",0);
			if ( g_strv_length(tokens) == 3 ) {
				if ( cpts ) {
					cpts->checkedRef = cpts->checkedRef + g_ascii_strtoull(tokens[0],NULL,10);
					cpts->updatedRef = cpts->updatedRef + g_ascii_strtoull(tokens[1],NULL,10);
					cpts->failedRef = cpts->failedRef + g_ascii_strtoull(tokens[2],NULL,10);
				}
				g_ptr_array_add(*gpa,g_strdup_printf("%s : References checked %s , updated %s , failed %s",id,tokens[0],tokens[1],tokens[2]));
			} else {
				g_ptr_array_add(*gpa,g_strdup_printf("%s : %s",id, *tmp));
			}
			g_strfreev (tokens);
		}
	}
}

	static void
_m1policy_update_thread(gpointer data, gpointer p)
{
	gs_error_t *err = NULL;
	GError *gerr=NULL;
	gchar **tmp=NULL;
	container_id_t cid;
	struct thread_user_data_s *user_data = (struct thread_user_data_s *)p;
	gchar *base = data;

	if(!hex2bin(base, cid, 2, &gerr)) {
		GRID_WARN("Invalid prefix: %d %s",gerr->code, gerr->message);
		g_clear_error(&gerr);
		return;
	}
	err = _m1policy_update(user_data->action,user_data->ns,TRUE,cid, "meta2", user_data->excludesrv, user_data->checkonly, &tmp);
	g_mutex_lock(user_data->lock);
	_pack_result(&(user_data->gpa),base, tmp, err, user_data->cpts);
	user_data->indexreach ++;
	g_mutex_unlock(user_data->lock);
	if ( err ) {
		gs_error_free(err);
		err = NULL;
	}
	if ( tmp )
		g_strfreev (tmp);

}

	gs_error_t*
hcadmin_meta1_policy_update(char *ns,gchar *action, gboolean checkonly, gchar **globalresult, gchar ***result, char ** args)
{
	gs_error_t    *err     = NULL;
	GPtrArray     *gpa     = NULL;
	gchar         *m1pAction  = NULL;
	struct global_cpt_s *cpts = NULL;
	gchar         *excludesrv = NULL;
	gchar         *srvtype = "meta2";
	gchar         *hexID   = NULL;
	GError        *gerr    = NULL;
	container_id_t cid;
	gchar        **tmp     = NULL;

	if ((!args) || ( g_strv_length(args) == 0)) {
		GSERRORCODE(&err,500, "Invalid argument list\n");
		goto failed;
	}

	// extract ID
    hexID = args[0];

	// extract specific arg / action type
	if ( g_strcmp0(action, "meta1_policy_apply") == 0) {
		m1pAction = g_strdup_printf("UPDATE");
		if ( g_strv_length(args) > 1 )
			if (strlen(args[1]) > 0)
	            srvtype = args[1];

	} else if ( g_strcmp0(action, "meta1_policy_exclude") == 0 ) {
		m1pAction = g_strdup_printf("EXCLUDE");
		if ( g_strv_length(args) > 1 )
			excludesrv = args[1];
		else {
			GSERRORCODE(&err, 500, "Missing service url \n");
		}
	} else {	
		GSERRORCODE(&err, 500, "INVALID meta1 policy action %s\n",action);
	}
	if (err)
		goto failed;

	if ( g_strcmp0(hexID,"ALL") == 0) {
		guint idx;
		struct thread_user_data_s *user_data = NULL;
		GThreadPool *pool = NULL;
		cpts = g_malloc0(sizeof(struct global_cpt_s));
		user_data = g_malloc0(sizeof(struct thread_user_data_s));
		user_data->ns = ns;
		user_data->action = m1pAction;
		user_data->type = g_strdup_printf(srvtype);
		user_data->excludesrv = excludesrv;
		user_data->checkonly = checkonly;
		user_data->lock = g_mutex_new();
		user_data->indexreach=0;
		user_data->cpts = cpts;
		user_data->gpa = NULL;
		pool = g_thread_pool_new (_m1policy_update_thread,user_data,10,TRUE,&gerr);
		for ( idx=0; idx<65536 ;idx++) {
			gchar base[5];
			guint8 *prefix=(guint8 *)(&idx);
			g_snprintf(base, sizeof(base), "%02X%02X",
					prefix[0], prefix[1]);
			g_thread_pool_push(pool, g_strdup(base) ,&gerr);
			if ( gerr != NULL ) {
				GRID_WARN("Failed to push new data thread %d, %d %s",idx,gerr->code,gerr->message);
				g_clear_error(&gerr);
				gerr = NULL;
			}
		}
		guint lastindex = 0;
		while(1) {
			if ( user_data->indexreach - lastindex > 500) {
				lastindex = user_data->indexreach;
				GRID_INFO("%d prefix checked",user_data->indexreach);
			}
			if ( user_data->indexreach >= 65536 )
				break;
			usleep(1000000);
		}
		if ( excludesrv && excludesrv[0] ) {
			struct hc_url_s *url = NULL;
			url = hc_url_empty();
			hc_url_set(url,HCURL_NS,ns);
			m2v2_remote_execute_EXITELECTION(excludesrv,NULL,url);
			hc_url_clean(url);
		}
		g_thread_pool_free(pool, FALSE, TRUE);
		g_mutex_free(user_data->lock);
		g_free(user_data);
		gpa = user_data->gpa;

	} else {
		// prefix ??
		if ( strlen(hexID) == 4 ) {
			if(!hex2bin(hexID, cid, 2, &gerr)) {
				GSERRORCAUSE(&err, gerr, "Invalid prefix\n");
				goto failed;
			}
			err = _m1policy_update(m1pAction,ns,TRUE,cid, srvtype, excludesrv, checkonly, &tmp);
			_pack_result(&gpa,hexID,tmp,err,NULL);
			if ( err ) {
				gs_error_free(err);
				err = NULL;
			} else {
				if ( excludesrv && excludesrv[0] ) {
					struct hc_url_s *url = NULL;
					url = hc_url_empty();
					hc_url_set(url,HCURL_NS,ns);
					m2v2_remote_execute_EXITELECTION(excludesrv,NULL,url);
					hc_url_clean(url);
				}
			}

		// CID ??
		} else if (strlen(hexID) == 64 ) {
			if (!hex2bin(hexID, cid, sizeof(container_id_t), &gerr)) {
				GSERRORCAUSE(&err, gerr, "Invalid container_id\n");
				goto failed;
			}
			err = _m1policy_update(m1pAction,ns,FALSE,cid, srvtype, excludesrv, checkonly, &tmp);
			_pack_result(&gpa,hexID,tmp,err,NULL);
			if ( err ) {
				gs_error_free(err);
				err = NULL;
			} else {
				if ( excludesrv && excludesrv[0] ) {
					struct hc_url_s *url = NULL;
					url = hc_url_empty();
					hc_url_set(url,HCURL_NS,ns);
					hc_url_set(url,HCURL_HEXID,hexID);
					m2v2_remote_execute_EXITELECTION(excludesrv,NULL,url);
					hc_url_clean(url);
				}
			}

		// other ? --> error
		} else {
			GSERRORCODE(&err,500,"invalid ID %s, %d \n",hexID, sizeof(hexID));
		}
	}

	// free all memory
	if ( gerr)
		g_clear_error(&gerr);

	if ( gpa ) {
		g_ptr_array_add(gpa, NULL);
		if ( cpts ) {
			*globalresult = g_strdup_printf("Global result : References checked %lu , updated %lu , failed %lu",cpts->checkedRef,cpts->updatedRef,cpts->failedRef);
		}
		*result = (gchar**)g_ptr_array_free(gpa,FALSE);
	}
	if ( tmp )
		g_strfreev (tmp);
	if ( cpts )
		g_free(cpts);

failed :
	if (m1pAction)
		g_free(m1pAction);

	return err;
}




gs_error_t * hcadmin_touch(char *url,gchar *action, gboolean checkonly, gchar **globalresult, gchar ***result, char ** args)
{
	gchar *option = NULL;
	guint32 flags = 0;
	gs_error_t *err = NULL;
	struct hc_url_s *hcurl = NULL;

	(void) action;
	(void) checkonly;
	(void) result;

	/* check poptionnal option*/
	if (args != NULL) {
		option = args[0];
		if ( g_strcmp0(option,"UPDATE_CSIZE") == 0) {
			flags = META2TOUCH_FLAGS_UPDATECSIZE;

		} else if ( g_strcmp0(option,"RECALC_CSIZE") == 0) {
			flags = META2TOUCH_FLAGS_RECALCCSIZE;

		} else {
			if ((option) && (strlen(option) > 0)) {
				GSERRORCODE(&err,-1,"invalid option %s\n", option);
				return err;
			}
		} 
	}

	/* check and convert NS/REF/PATH */
	if (!(hcurl = hc_url_init(url))) {
		GSERRORCODE(&err,-1,"invalid URL: %s\n", url);
		return err;
	}

	err = _m2_touch(hcurl, flags);
	if (!err) {
		*globalresult = g_strdup_printf("TOUCH done for %s", url);
	}
	hc_url_clean(hcurl);
	return err;
}


