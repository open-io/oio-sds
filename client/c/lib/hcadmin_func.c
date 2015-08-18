/*
OpenIO SDS client
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include "./gs_internals.h"
#include "./hcadmin.h"

static gs_error_t *
_m2_touch(struct hc_url_s *hcurl, guint32 flags)
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
	container_name = hc_url_get(hcurl, HCURL_USER);
	content        = hc_url_get(hcurl, HCURL_PATH);

	hc = gs_grid_storage_init(ns, &gserr);
	if (!hc) {
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
	m2list = gs_resolve_meta2(hc, hcurl, &err);		
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
		err = m2v2_remote_touch_content(str_addr, hcurl);
	else 
		err = m2v2_remote_touch_container_ex(str_addr, hcurl, flags);
	
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

gs_error_t *
hcadmin_touch(char *url, gchar *action, gboolean checkonly, gchar **globalresult, gchar ***result, char ** args)
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
	if (!(hcurl = hc_url_oldinit(url))) {
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

