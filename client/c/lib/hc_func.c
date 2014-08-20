#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "hc.tools"
#endif

#include <getopt.h>

#include "./gs_internals.h"
#include "./hc.h"

#define ERR_MISSING_SNAPSHOT_IN_URL "Missing snapshot name in URL"

struct ls_utils_s {
	char *path;
	gint64 version;
	char *str;
	gboolean deleted;
};

struct list_content_s {
	GString *buffer;
	guint32 nb_elts;
	gboolean xml;
	gboolean show_info;
	GSList *listed;
};

/* --------------------------- UTILS FUNCTIONS ------------------------------ */

static gs_error_t *
_dl_nocache(gs_container_t *c, struct hc_url_s *url, const char *local_path,
		gs_download_info_t *dlinfo, gchar *stgpol)
{
	gs_error_t *e = NULL;
	GError *err = NULL;
	gs_content_t *content = NULL;
	namespace_info_t *ni = NULL;
	GSList *filtered = NULL, *beans = NULL;

	/*find the content*/
	content  = gs_get_content_from_path_full(c, hc_url_get(url, HCURL_PATH),
			hc_url_get(url, HCURL_SNAPORVERS), &filtered, &beans, &e);

	if(NULL != content) {
		GRID_DEBUG("Content %s found in container %s\n",
				hc_url_get(url, HCURL_PATH), hc_url_get(url, HCURL_REFERENCE));

		ni = get_namespace_info(hc_url_get(url, HCURL_NS), &err);
		if (!ni) {
			GSERRORCAUSE(&e, err, "Cannot get namespace info for NS [%s]",
					hc_url_get(url, HCURL_NS));
			g_clear_error(&err);
			return e;
		}

		namespace_info_copy(ni, &(content->info.container->info.gs->ni), &err);

		/*download the content*/
		if (!gs_download_content_full (content, dlinfo, stgpol, filtered,
				beans, &e)) {
			g_printerr("Cannot download %s from %s (into %s)\n",
					hc_url_get(url, HCURL_PATH),
					hc_url_get(url, HCURL_REFERENCE),
					local_path ? local_path : "<stdout>");
		} else {
			GRID_DEBUG("Download done from %s to %s\n",
					hc_url_get(url, HCURL_PATH),
					local_path ? local_path : "<stdout>");
		}
		namespace_info_clear(ni);
		g_free(ni);
		gs_content_free (content);
		g_slist_free(filtered);
		_bean_cleanl2(beans);
		return e;
	}

	g_printerr("'%s' not found in '%s'\n", hc_url_get(url, HCURL_PATH),
			hc_url_get(url, HCURL_REFERENCE));
	return e;
}

static ssize_t
_feed_from_fd(void *uData, char *b, size_t bSize)
{
	ssize_t nbRead;

	if (!b || !bSize) {
		g_printerr("Invalid buffer for reading\n");
		return -1;
	}
	nbRead = read(*((int *) uData), b, bSize);
	return nbRead;
}

static void
_filter_info_xml(gs_content_t *content, struct list_content_s *lc)
{
	struct ls_utils_s *lu = NULL;
	lu = g_malloc0(sizeof(struct ls_utils_s));
	GString *tmp = g_string_new("");
	lu->path = g_strdup(content->info.path);
	lu->deleted = content->deleted;
	lu->version = g_ascii_strtoll(content->version, NULL, 10);
	// content->gba_sysmd->data doesn't end with '\0'
	gchar *sysmd = g_strndup((const gchar*)content->gba_sysmd->data,
			content->gba_sysmd->len);
	g_string_append_printf(tmp, 	"  <Content>\n"
			"   <Path>%s</Path>\n"
			"   <Size>%"G_GINT64_FORMAT"</Size>\n"
			"   <Version>%s</Version>\n"
			"   <MdSys>%s</MdSys>\n"
			"   <Deleted>%d</Deleted>\n"
			"  </Content>\n",
			content->info.path, content->info.size,
			content->version, sysmd,
			content->deleted);
	g_free(sysmd);
	lu->str = g_string_free(tmp, FALSE);
	lc->listed = g_slist_prepend(lc->listed, lu);

}

static void
_filter_info(gs_content_t *content, struct list_content_s *lc)
{
	struct ls_utils_s *lu = NULL;
	lu = g_malloc0(sizeof(struct ls_utils_s));
	GString *tmp = g_string_new("");
	lu->path = g_strdup(content->info.path);
	lu->deleted = content->deleted;
	lu->version = g_ascii_strtoll(content->version, NULL, 10);

	g_string_append_printf(tmp, "%"G_GINT64_FORMAT" %s %s", content->info.size,
			content->version, content->info.path);
	if(content->deleted)
		tmp = g_string_append(tmp, " (deleted)\n");
	else
		tmp = g_string_append(tmp, "\n");
	lu->str = g_string_free(tmp, FALSE);
	lc->listed = g_slist_prepend(lc->listed, lu);
}

static int
_my_content_filter(gs_content_t * content, void *user_data)
{
	gs_error_t *err = NULL;
	static gs_content_info_t info;
	struct list_content_s *lc = (struct list_content_s *)user_data;

	if (!content)
		return -1;

	if (!gs_content_get_info(content, &info, &err)) {
		g_printerr("cannot read the information about a content (%s)\n", gs_error_get_message(err));
		gs_error_free(err);
		return -1;
	}

	if(lc->show_info) {
		/* load content info from meta2 */
		if(!gs_content_reload(content, TRUE, FALSE, &err)) {
			g_printerr("Failed to get content informations from meta2 : (%s)\n", gs_error_get_message(err));
			gs_error_free(err);
			return -1;
		}
		if(lc->xml)
			_filter_info_xml(content, lc);
		else
			_filter_info(content, lc);
	} else {
		struct ls_utils_s *lu = g_malloc0(sizeof(struct ls_utils_s));
		lu->path = g_strdup(content->info.path);
		lu->deleted = content->deleted;
		lu->version = g_ascii_strtoll(content->version, NULL, 10);
		GString *tmp = g_string_new("");
		if (lc->xml) {
			g_string_append_printf(tmp, "  <Content>\n");
			g_string_append_printf(tmp, "   <Path>%s</Path>\n"
					"  </Content>\n",info.path);
		} else {
			g_string_append_printf(tmp, "%s\n", info.path);
		}
		lu->str = g_string_free(tmp, FALSE);
		lc->listed = g_slist_prepend(lc->listed, lu);
	}
	return 1;
}

static int
_open_destination(const char *local_path, int force, int *out)
{
	/* Allow everything except execution (umask will apply) */
	mode_t file_perms = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IWOTH|S_IROTH;

	if (!local_path || !g_ascii_strcasecmp(local_path, "-")) {
		*out = 1;
	}
	else {
		*out = open(local_path, O_WRONLY | O_CREAT | (force ? O_TRUNC : O_EXCL),
				file_perms);
		if (-1 == *out) {
			if (errno == ENOENT) {
				*out = open(local_path, O_WRONLY | O_CREAT | O_EXCL, file_perms);
				if (-1 == *out) {
					g_printerr("Cannot create and open the local file %s (%s)\n", local_path,
					    strerror(errno));
					return 0;
				} else {
					g_printerr("Local path %s created\n", local_path);
				}
			} else {
				g_printerr("Cannot open the local file %s (%s)\n", local_path, strerror(errno));
				return 0;
			}
		} else {
			GRID_DEBUG("Local path %s opened\n", local_path);
		}
	}
	return 1;
}

static ssize_t
_write_to_fd(void *uData, const char *b, const size_t bSize)
{
	ssize_t nbW;

	nbW = write(*((int *) uData), b, bSize);
	return nbW;
}


/*----------------------- PUBLIC FUNCTIONS ---------------------------------- */

gs_error_t *
hc_create_container(gs_grid_storage_t *hc, struct hc_url_s *url,
		const char *stgpol, const char *versioning)
{
	GError *err = NULL;
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;
	struct m2v2_create_params_s params = {stgpol, versioning, FALSE};

	c = gs_get_storage_container2(hc, hc_url_get(url, HCURL_REFERENCE),
			&params, 0, &e);

	if (c != NULL) {
		gchar m2[STRLEN_ADDRINFO] = {0};
		addr_info_to_string(&(c->meta2_addr), m2, STRLEN_ADDRINFO);
		err = m2v2_remote_execute_HAS(m2, NULL, url);
		if (err == NULL) {
			e = gs_error_new(CODE_CONTAINER_EXISTS,
					"Failed to create container [%s]: "
					"container already exists in namespace [%s]\n",
					hc_url_get(url, HCURL_REFERENCE), hc_url_get(url, HCURL_NS));
			goto end_label;
		} else if (err->code != CODE_CONTAINER_NOTFOUND) {
			GSERRORCAUSE(&e, err,
					"Failed to check container existence in meta2: ");
			goto end_label;
		} else {
			GRID_WARN("Container exists in meta1 but not in meta2");
		}
	}

	gs_error_free(e);
	e = NULL;
	c = gs_get_storage_container2(hc, hc_url_get(url, HCURL_REFERENCE),
			&params, 1, &e);

	if (c)
		GRID_INFO("Container [%s] created in namespace [%s].\n\n",
				hc_url_get(url, HCURL_REFERENCE), hc_url_get(url, HCURL_NS));

end_label:
	gs_container_free(c);
	g_clear_error(&err);

	return e;
}

static gs_error_t *
hc_upload_content(gs_grid_storage_t *hc, struct hc_url_s *url, const char *local_path,
		const char *stgpol, const char *sys_metadata, int ac, gboolean is_append)
{
	int in = -1;
	struct stat64 s;
	gs_container_t *c = NULL;
	gs_error_t *e = NULL;

	/*init the local path */
	if (-1 == stat64(local_path, &s)) {
		e = g_malloc0(sizeof(gs_error_t));
		e->code = errno;
		e->msg = g_strdup_printf("Cannot stat the local file (%s)\n", strerror(errno));
		return e;
	}
	GRID_DEBUG("Local path %s found\n", local_path);

	if (-1 == (in = open(local_path, O_RDONLY|O_LARGEFILE))) {
		e = g_malloc0(sizeof(gs_error_t));
		e->code = errno;
		e->msg = g_strdup_printf("Cannot open the local file (%s)\n", strerror(errno));
		goto end_put;
	}
	GRID_DEBUG("Local path %s found and opened\n", local_path);

	if(!(c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE), NULL, ac, &e))) {
		g_printerr("Failed to resolve and/or create meta2 entry for reference %s\n",
				hc_url_get(url, HCURL_REFERENCE));
		goto end_put;
	}

	/*upload the content */
	if (is_append) {
		if (!gs_append_content(c, hc_url_get(url, HCURL_PATH), s.st_size, _feed_from_fd, &in, &e)) {
			goto end_put;
		}
	} else {
		if (!gs_upload(c, hc_url_get(url, HCURL_PATH), s.st_size, _feed_from_fd,
				&in, NULL, sys_metadata, stgpol, &e)) {
			goto end_put;
		}
	}
	GRID_INFO("Uploaded a new version of content [%s] in container [%s]\n\n",
			hc_url_get(url, HCURL_PATH), hc_url_get(url, HCURL_REFERENCE));
	GRID_DEBUG("Content successfully uploaded!\n");

end_put:

	/** FIXME TODO XXX why not (in >= 0) or (in > -1) ? */
	if (in > 1)
		metautils_pclose(&in);

	if(NULL != c) {
		gs_container_free(c);
		c = NULL;
	}

	return e;
}

gs_error_t *
hc_put_content(gs_grid_storage_t *hc, struct hc_url_s *url, const char *local_path,
		const char *stgpol, const char *sys_metadata, int ac)
{
	return hc_upload_content(hc, url, local_path, stgpol, sys_metadata, ac, FALSE);
}

gs_error_t *
hc_func_copy_content(gs_grid_storage_t *hc, struct hc_url_s *url, const char *source)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE), NULL, 0, &e);
	if(NULL != c) {
		hc_copy_content(c, source, hc_url_get(url, HCURL_PATH), &e); 
		gs_container_free(c);
	}
	return e;
}

gs_error_t *
hc_append_content(gs_grid_storage_t *hc, struct hc_url_s *url, const char *local_path)
{
	return hc_upload_content(hc, url, local_path, NULL, NULL, FALSE, TRUE);
}

static gboolean
_is_last_version(struct ls_utils_s *lu, struct list_content_s *lc)
{
	GSList *l = NULL;
	for (l = lc->listed; l && l->data; l = l->next) {
		struct ls_utils_s *cursor = (struct ls_utils_s *) l->data;
		if (!strcmp(lu->path, cursor->path)) {
			if (cursor->version > lu->version) {
				return FALSE;
			}
		}
	}
	return TRUE;
}

static void
_sort_listed(struct list_content_s *lc)
{
	GSList *l = NULL;
	for(l = lc->listed ; l && l->data; l = l->next) {
		struct ls_utils_s *lu = (struct ls_utils_s*) l->data;
		if(lc->show_info) {
			lc->buffer = g_string_append(lc->buffer, ((struct ls_utils_s *) l->data)->str);
			lc->nb_elts ++;
		} else {
			// If last version deleted, do not show anything in listings
			if((!lu->deleted) && (_is_last_version(lu, lc))) {
			// If last version deleted, show most recent not deleted version
				lc->buffer = g_string_append(lc->buffer, ((struct ls_utils_s *) l->data)->str);
				lc->nb_elts ++;
			}
		}
	}
}

gs_error_t *
hc_list_contents(gs_grid_storage_t *hc, struct hc_url_s *url, int output_xml, int show_info,
		char **result)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;
	const gchar *snapshot = hc_url_get(url, HCURL_SNAPORVERS);
	struct list_content_s lc;

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE), NULL, 0, &e);

	if (NULL != c) {
		GRID_DEBUG("%s found\n", hc_url_get(url, HCURL_REFERENCE));

		lc.nb_elts = 0;
		lc.xml = output_xml;
		lc.show_info = show_info;
		lc.buffer = g_string_new("");
		lc.listed = NULL;

		if(output_xml) {
			g_string_append_printf(lc.buffer,
					"<Container>\n"
					" <Name>%s</Name>\n"
					" <Contents>\n",
					hc_url_get(url, HCURL_REFERENCE));
		} else {
			g_string_append_printf(lc.buffer, "#Listing container=[%s]\n", hc_url_get(url, HCURL_REFERENCE));
		}

		if (!gs_list_container_snapshot(c, NULL, _my_content_filter, &lc,
				snapshot, &e)) {
			g_printerr("Cannot list %s\n", hc_url_get(url, HCURL_REFERENCE));
			g_string_free(lc.buffer, TRUE);
		} else {
			_sort_listed(&lc);
			GRID_DEBUG("%s listed\n", hc_url_get(url, HCURL_REFERENCE));
			if(output_xml) {
				lc.buffer = g_string_append(lc.buffer,
					" </Contents>\n"
					"</Container>\n");
			} else {
				g_string_append_printf(lc.buffer, "#Total in [%s]: %i elements\n",
						hc_url_get(url, HCURL_REFERENCE), lc.nb_elts);
			}
			*result = g_string_free(lc.buffer, FALSE);
		}

		gs_container_free(c);
		return e;
	}

	g_printerr("Cannot find %s\n", hc_url_get(url, HCURL_REFERENCE));
	return e;
}

gs_error_t *
hc_get_content(gs_grid_storage_t *hc, struct hc_url_s *url, const char *local_path, int force, int cache, gchar *stgpol)
{
	gs_error_t *e = NULL;
	/* download a content */
	gs_download_info_t dl_info;
	gs_container_t *c = NULL;
	int out = 0;

	memset(&dl_info, 0x00, sizeof(dl_info));

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE), NULL, 0, &e);

	if(NULL != c) {
		if(_open_destination(local_path, force, &out)) {
			GRID_DEBUG("Destination file descriptor ready fd=%d path=%s\n", out, local_path ? local_path : "<stdout>");
			/*download the content */
			dl_info.offset = 0;
			dl_info.size = 0;
			dl_info.writer = _write_to_fd;
			dl_info.user_data = &out;
			if (cache) {
				gs_download_content_by_name_full(c, hc_url_get(url, HCURL_PATH),
						hc_url_get(url, HCURL_SNAPORVERS), stgpol, &dl_info, &e);
			} else {
				e = _dl_nocache(c, url, local_path, &dl_info, stgpol);
			}

			if (out >= 0) {
				metautils_pclose(&out);
			}
		} else {
			gchar tmp[256];
			bzero(tmp, sizeof(tmp));
			g_snprintf(tmp, sizeof(tmp), "Failed to open the destination file descriptor to path=%s\n", local_path ? local_path : "<stdout>");
			e = g_malloc0(sizeof(gs_error_t));
			e->code = 0;
			e->msg = g_strdup(tmp);
		}

		gs_container_free(c);

	} else {
		g_printerr("Failed to resolve meta2 entry for reference %s\n",
				hc_url_get(url, HCURL_REFERENCE));
	}

	return e;
}

gs_error_t *
hc_object_info(gs_grid_storage_t *hc, struct hc_url_s *url, int xml, char **result)
{
	struct loc_context_s *lc = NULL;
	gs_error_t *e = NULL;
	lc = loc_context_init_retry(hc, url, &e);
	if (!lc)
		return e;
	
	*result = loc_context_to_string(lc, xml);

	loc_context_clean(lc);

	return NULL;
}

gs_error_t *
hc_delete_content(gs_grid_storage_t *hc, struct hc_url_s *url)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;
	gs_content_t *content = NULL;

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE),NULL, 0, &e);
	if(NULL != c) {
		const gchar *version = hc_url_get(url, HCURL_VERSION);
		// First try
		content = gs_get_content_from_path_and_version (c, hc_url_get(url, HCURL_PATH), version, &e);
		if (content == NULL && e != NULL && e->code == CODE_CONTENT_NOTFOUND && !version) {
			// Last version is probably marked deleted, so a "get" without
			// version fails. We need to specify we want the latest, even
			// if it's deleted, so we can undelete it.
			version = HCURL_LATEST_VERSION;
			gs_error_free(e);
			e = NULL;
			// Second try
			content = gs_get_content_from_path_and_version (c, hc_url_get(url, HCURL_PATH), version, &e);
		}
		if (NULL != content) {
			if(gs_destroy_content (content, &e)) {
				GRID_DEBUG("Content %s deleted\n", hc_url_get(url, HCURL_PATH));
			}
			gs_content_free(content);
		}
		gs_container_free(c);
	}
	return e;
}

gs_error_t *
hc_delete_container(gs_grid_storage_t *hc, struct hc_url_s *url, int force, int flush)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;
	unsigned int flags = 0;

	if (force) flags |= M2V2_DESTROY_FORCE;

	// to flush by meta2, but without event generated
	//if (flush) flags |= M2V2_DESTROY_FLUSH;

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE), NULL, 0, &e);
	if(NULL != c) {

		// to flush by this process, but with event generated
		if (flush) {
			if (gs_flush_container(c, &e)) {
				GRID_DEBUG("Container flushed\n");
		    }
		}

		// destroy container
		if (!e) {
			if (gs_destroy_container_flags (c, flags, &e)) {
				GRID_DEBUG("Container deleted\n");
			}
		}
		gs_container_free(c);
	}
	return e;
}

gs_error_t *
hc_func_set_property(gs_grid_storage_t *hc, struct hc_url_s *url,
	char ** args)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;
	gs_content_t *content = NULL;

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE),
			NULL, 0, &e);
	if (NULL != c) {
		if (hc_url_has(url, HCURL_PATH)) {
			content = gs_get_content_from_path_and_version (c,
					hc_url_get(url, HCURL_PATH), hc_url_get(url, HCURL_VERSION),
					&e);
			if (NULL != content) {
				gchar **props = g_malloc0(sizeof(gchar*) * 2);
				props[0] = g_strdup_printf("%s=%s", args[0], args[1]);
				props[1] = NULL;
				hc_set_content_property(content, props, &e);
				gs_content_free(content);
				g_strfreev(props);
			}
		} else {
			e = hc_set_container_global_property(c, args[0], args[1]);
		}
		gs_container_free(c);
	}
	return e;
}

gs_error_t *
hc_func_get_content_properties(gs_grid_storage_t *hc, struct hc_url_s *url, char ***result)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;
	gs_content_t *content = NULL;

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE), NULL, 0, &e);
	if (NULL != c) {
		if (hc_url_has(url, HCURL_PATH)) {
			content = gs_get_content_from_path_and_version (c,
					hc_url_get(url, HCURL_PATH), hc_url_get(url, HCURL_VERSION),
					&e);
			if(NULL != content) {
				hc_get_content_properties(content,result,&e);
				gs_content_free(content);
			}
		} else {
			e = hc_get_container_global_properties(c, result);
		}
		gs_container_free(c);
	}
	return e;
}

gs_error_t *
hc_func_delete_property(gs_grid_storage_t *hc, struct hc_url_s *url, char **keys)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;
	gs_content_t *content = NULL;

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE), NULL, 0,
			&e);
	if (NULL != c) {
		if (hc_url_has(url, HCURL_PATH)) {
			content = gs_get_content_from_path_and_version (c,
					hc_url_get(url, HCURL_PATH), hc_url_get(url, HCURL_VERSION),
					&e);
			if (NULL != content) {
				hc_delete_content_property(content, keys, &e);
				gs_content_free(content);
			}
		} else {
			e = hc_del_container_global_property(c, keys[0]);
		}
		gs_container_free(c);
	}
	return e;
}

gs_error_t *
hc_func_list_snapshots(gs_grid_storage_t *hc, struct hc_url_s *url,
		int output_xml, int show_info, char **result)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;
	struct list_content_s lc;
	redc_snapshot_t **snapshots = NULL;

	c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE),
			NULL, 0, &e);
	if (c != NULL) {
		lc.nb_elts = 0;
		lc.xml = output_xml;
		lc.show_info = show_info;
		lc.buffer = g_string_new("");
		lc.listed = NULL;

		e = redc_list_snapshots(c, &snapshots);
		if (e == NULL) {
			int i = 0;
			redc_snapshot_t *snap = snapshots[i];
			if (output_xml) {
				g_string_append_printf(lc.buffer,
						"<Container>\n"
						" <Name>%s</Name>\n"
						" <Snapshots>\n",
					hc_url_get(url, HCURL_REFERENCE));
			} else {
				g_string_append_printf(lc.buffer,
						"#Listing snapshots of container=[%s]\n",
						hc_url_get(url, HCURL_REFERENCE));
			}
			for (; snap != NULL; ++i, snap = snapshots[i]) {
				const char *name = redc_snapshot_get_name(snap);
				lc.nb_elts++;
				if (lc.xml) {
					g_string_append_printf(lc.buffer, "  <Snapshot>\n");
					g_string_append_printf(lc.buffer, "   <Name>%s</Name>\n"
							"  </Snapshot>\n", name);
				} else {
					g_string_append_printf(lc.buffer, "%s\n", name);
				}
			}
			if (output_xml) {
				g_string_append_printf(lc.buffer,
						" </Snapshots>\n"
						"</Container>\n");
			} else {
				g_string_append_printf(lc.buffer,
						"#Total in [%s]: %i elements\n",
						hc_url_get(url, HCURL_REFERENCE), lc.nb_elts);
			}
			*result = g_string_free(lc.buffer, FALSE);
			redc_snapshot_array_clean(snapshots);
		}
		gs_container_free(c);
	}
	return e;
}

typedef gs_error_t* (*snap_func)(gs_container_t *container,
		const char *snapshot_name, void *param);

/* Generic function to avoid code duplication */
static gs_error_t *
_hc_func_snapshot_generic(snap_func func, gs_grid_storage_t *hc,
		struct hc_url_s *url, void *param)
{
	gs_error_t *e = NULL;
	gs_container_t *c = NULL;
	const gchar *snap_name = hc_url_get(url, HCURL_SNAPORVERS);
	if (snap_name == NULL) {
		GSERRORSET(&e, ERR_MISSING_SNAPSHOT_IN_URL);
	} else {
		c = gs_get_storage_container(hc, hc_url_get(url, HCURL_REFERENCE),
				NULL, 0, &e);
		if (c != NULL) {
			e = func(c, snap_name, param);
			gs_container_free(c);
		}
	}
	return e;
}

gs_error_t *
hc_func_take_snapshot(gs_grid_storage_t *hc, struct hc_url_s *url)
{
	gs_error_t* wrap_redc_take_snapshot(gs_container_t *c,
			const char *snap, void *param) {
		(void) param;
		return redc_take_snapshot(c, snap);
	}

	return _hc_func_snapshot_generic(wrap_redc_take_snapshot, hc, url, NULL);
}

gs_error_t *
hc_func_delete_snapshot(gs_grid_storage_t *hc, struct hc_url_s *url)
{
	gs_error_t* wrap_redc_delete_snapshot(gs_container_t *c,
			const char *snap, void *param) {
		(void) param;
		return redc_delete_snapshot(c, snap);
	}

	return _hc_func_snapshot_generic(wrap_redc_delete_snapshot, hc, url, NULL);
}

gs_error_t *
hc_func_restore_snapshot(gs_grid_storage_t *hc, struct hc_url_s *url,
		int hard_restore)
{
	const char *content = hc_url_get(url, HCURL_PATH);
	gs_error_t* wrap_redc_restore_snapshot(gs_container_t *c,
			const char *snap, void *param) {
		// FIXME
		if (content != NULL)
			return redc_restore_snapshot_alias(c, content, snap);
		else
			return redc_restore_snapshot(c, snap, *(int*)param);
	}

	return _hc_func_snapshot_generic(wrap_redc_restore_snapshot, hc, url,
			&hard_restore);
}

