#include "./gs_internals.h"

gint
chunkinfo_sort_position_ASC(gconstpointer c1, gconstpointer c2)
{
	gint64 pos1, pos2, res;
	gint mapped_res;

	pos1 = ((const chunk_info_t *) c1)->position;
	pos2 = ((const chunk_info_t *) c2)->position;
	res = pos1 - pos2;
	mapped_res = res;
	return mapped_res;
}

gint
chunkinfo_sort_position_DESC(gconstpointer c1, gconstpointer c2)
{
	gint64 pos1, pos2, res;
	gint mapped_res;

	pos1 = ((const chunk_info_t *) c1)->position;
	pos2 = ((const chunk_info_t *) c2)->position;
	res = pos2 - pos1;
	mapped_res = res;
	return mapped_res;
}

void
gs_error_set_cause(gs_error_t ** err, GError * gErr, const char *format, ...)
{
	char *tmpCode = NULL, *tmpCause = NULL, *tmpFinal = NULL;

	if (!err)
		return;

	if (gErr) {
		tmpCode = g_strdup_printf("(code=%i) ", gErr->code);
	}
	else {
		if (*err)
			tmpCode = g_strdup_printf("(code=%i) ", (*err)->code);
		else
			tmpCode = g_strdup("(code=0) ");
	}

	if (format) {
		va_list args;

		va_start(args, format);
		tmpCause = g_strdup_vprintf(format, args);
		va_end(args);
	}
	else {
		tmpCause = g_strdup("unknown cause");
	}

	if (!tmpCause || !tmpCode) {
		ALERT("memory allocation failure");
		if (tmpCode)
			g_free(tmpCode);
		if (tmpCause)
			g_free(tmpCause);
		return;
	}

#ifdef HAVE_ANNOYING_DEBUG_TRACES
# define ERROR_SEPARATOR "\r\n\t--- directory error ---\r\n\t"
#else
# define ERROR_SEPARATOR " "
#endif

	if (*err && (*err)->msg) {
		if (gErr && gErr->message)
			tmpFinal =
			    g_strconcat(tmpCode, tmpCause, "\r\n\t", gErr->message,
						ERROR_SEPARATOR, (*err)->msg, NULL);
		else
			tmpFinal = g_strconcat(tmpCode, tmpCause, "\r\n\t", (*err)->msg, NULL);
		free((*err)->msg);
		(*err)->msg = NULL;
	}
	else {
		if (gErr && gErr->message)
			tmpFinal =
			    g_strconcat(tmpCode, tmpCause, ERROR_SEPARATOR, gErr->message, NULL);
		else
			tmpFinal = g_strconcat(tmpCode, tmpCause, NULL);
		if (*err)
			(*err)->msg = NULL;
	}

	g_free(tmpCode);
	g_free(tmpCause);

	if (!tmpFinal) {
		ALERT("Memory allocation failure");
		return;
	}

	if (!*err && !(*err = calloc(1, sizeof(gs_error_t)))) {
		g_free(tmpFinal);
		ALERT("Memory allocation failure");
		return;
	}

	(*err)->msg = calloc(strlen(tmpFinal) + 1, 1);
	strcpy((*err)->msg, tmpFinal);
	g_free(tmpFinal);

	if (gErr)
		(*err)->code = gErr->code;
}

static void
gs_error_vset(gs_error_t ** err, int code, const char *fmt, va_list args)
{
	char *tmpCode = NULL, *tmpCause = NULL, *tmpFinal = NULL;

	if (!err)
		return;

	tmpCode = g_strdup_printf("(code=%i) ", code);

	if (fmt)
		tmpCause = g_strdup_vprintf(fmt, args);
	else
		tmpCause = g_strdup("Unknown cause");

	if (!tmpCause || !tmpCode) {
		if (tmpCause)
			g_free(tmpCause);
		if (tmpCode)
			g_free(tmpCode);
		ALERT("Memory allocation failure");
		return;
	}

	if (*err && (*err)->msg) {
		tmpFinal = g_strconcat(tmpCode, tmpCause, "\r\n\t", (*err)->msg, NULL);
		free((*err)->msg);
		(*err)->msg = NULL;
	}
	else {
		tmpFinal = g_strconcat(tmpCode, tmpCause, NULL);
		if (*err)
			(*err)->msg = NULL;
	}

	g_free(tmpCode);
	g_free(tmpCause);

	if (!tmpFinal) {
		ALERT("Memory allocation failure");
		return;
	}

	if (!*err && !(*err = calloc(1, sizeof(gs_error_t)))) {
		g_free(tmpFinal);
		ALERT("Memory allocation failure");
		return;
	}

	(*err)->msg = calloc(strlen(tmpFinal) + 1, 1);
	strcpy((*err)->msg, tmpFinal);
	g_free(tmpFinal);

	if (code)
		(*err)->code = code;
}

gs_error_t *
gs_error_new(int code, const char *fmt, ...)
{
	gs_error_t *error_new = NULL;
	va_list args;

	if (!fmt)
		return NULL;
	va_start(args, fmt);
	gs_error_vset(&error_new, code, fmt, args);
	va_end(args);
	return error_new;
}

void
gs_error_set(gs_error_t ** err, int code, const char *fmt, ...)
{
	va_list args;

	if (!fmt)
		return;
	va_start(args, fmt);
	gs_error_vset(err, code, fmt, args);
	va_end(args);
}

void
gs_error_free(gs_error_t * err)
{
	if (err) {
		if (err->msg)
			free(err->msg);
		err->msg = NULL;
		free(err);
	}
}

const char *
gs_error_get_message(gs_error_t * err)
{
	if (!err)
		return "error not set";
	if (!err->msg)
		return "error message not set";
	return err->msg;
}

int
gs_error_get_code(gs_error_t * err)
{
	if (!err)
		return -1;
	if (err->code < 0)
		return 0;
	return err->code;
}

void
gs_error_clear(gs_error_t ** err)
{
	if (!err)
		return;
	if (!*err)
		return;
	gs_error_free(*err);
	*err = NULL;
}

gboolean
gs_url_split(const gchar * url, gchar ** host, gchar ** port)
{
	int wrkUrl_len;
	gchar *wrkUrl = NULL;

	if (!host || !port)
		return FALSE;

	wrkUrl = g_strdup(url);
	wrkUrl_len = strlen(wrkUrl);

	if (*wrkUrl == '[') {	/*[IP]:PORT */
		
		gchar *last_semicolon;

		last_semicolon = g_strrstr(wrkUrl, ":");

		if (!last_semicolon)
			return FALSE;
		if (last_semicolon - wrkUrl >= wrkUrl_len) {
			return FALSE;
		}

		*(last_semicolon - 1) = '\0';
		*port = g_strdup(last_semicolon + 1);
		*host = g_strdup(wrkUrl + 1);
	}
	else {
		gchar *last_semicolon;

		last_semicolon = g_strrstr(wrkUrl, ":");

		if (!last_semicolon) {
			return FALSE;
		}
		if (last_semicolon - wrkUrl >= wrkUrl_len) {
			return FALSE;
		}

		*last_semicolon = '\0';
		*port = g_strdup(last_semicolon + 1);
		*host = g_strdup(wrkUrl);
	}
	g_free(wrkUrl);
	return TRUE;
}


void
gs_grid_storage_free(gs_grid_storage_t * gs)
{
	if (!gs)
		return;

	if (gs->direct_resolver)
		resolver_direct_free(gs->direct_resolver);

	if (gs->metacd_resolver)
		resolver_metacd_free(gs->metacd_resolver);

	if (gs->full_vns)
		free(gs->full_vns);
	if (gs->physical_namespace)
		free(gs->physical_namespace);

	namespace_info_clear(&(gs->ni));

	free(gs);
}


void
gs_container_free(gs_container_t * container)
{
	if (!container)
		return;
	gs_container_close_cnx(container);
	free(container);
}


void
gs_content_free(gs_content_t * content)
{
	if (!content)
		return;
	if (content->chunk_list) {
		g_slist_foreach(content->chunk_list, chunk_info_gclean, NULL);
		g_slist_free(content->chunk_list);
		content->chunk_list = NULL;
	}
	if (content->gba_md) {
		g_byte_array_free(content->gba_md, TRUE);
		content->gba_md = NULL;
	}
	if (content->gba_sysmd) {
		g_byte_array_free(content->gba_sysmd, TRUE);
		content->gba_sysmd = NULL;
	}
	if (content->version) {
		g_free(content->version);
		content->version = NULL;
	}
	if (content->policy) {
		g_free(content->policy);
		content->policy = NULL;
	}
	free(content);
}


void
gs_container_close_cnx(gs_container_t * container)
{
	if (container && container->meta2_cnx >= 0)
		metautils_pclose(&(container->meta2_cnx));
}


const char *
g_error_get_message(GError * err)
{
	if (!err)
		return "error not set";
	if (!err->message)
		return "error message not set";
	return err->message;
}

gs_status_t
gs_grid_storage_set_timeout(gs_grid_storage_t * gs, gs_timeout_t to, int val, gs_error_t ** err)
{
	int val_s;

	if (!gs) {
		GSERRORSET(err, "invalid grid_storage client parameter");
		return GS_ERROR;
	}

	if (val <= 0) {
		GSERRORSET(err, "invalid timer value (cannot be negative or null)");
		return GS_ERROR;
	}

	if ((int)to < (int)GS_TO_RAWX_CNX) {
		int i, ok = ~0;

		for (i = GS_TO_RAWX_CNX; i <= GS_TO_MCD_OP; i++) {
			ok &= gs_grid_storage_set_timeout(gs, i, to, NULL);
			if (!ok) {
				GSERRORSET(err, "<%s> some timeout haven't been set", __FUNCTION__);
				return GS_ERROR;
			}
			return GS_OK;
		}
	}

	else {
		if (to != GS_TO_RAWX_CNX && to != GS_TO_RAWX_OP && val < 100)
			INFO("<%s> small timer value (<100ms), use with caution", __FUNCTION__);

		switch (to) {
		case GS_TO_RAWX_CNX:
			val_s = val / 1000;
			if (!val_s || (val % 1000)) {
				val_s++;
				NOTICE("<%s> timeout on webdav connection rounded up to %d seconds", __FUNCTION__,
				    val_s);
			}
			gs->timeout.rawx.cnx = val_s * 1000;
			return GS_OK;
		case GS_TO_RAWX_OP:
			val_s = val / 1000;
			if (!val_s || (val % 1000)) {
				val_s++;
				NOTICE("<%s> timeout on webdav operation rounded up to %d seconds", __FUNCTION__,
				    val_s);
			}
			gs->timeout.rawx.op = val_s * 1000;
			return GS_OK;
		case GS_TO_M0_CNX:
			gs->direct_resolver->timeout.m0.cnx = val;
			return GS_OK;
		case GS_TO_M0_OP:
			gs->direct_resolver->timeout.m0.op = val;
			return GS_OK;
		case GS_TO_M1_CNX:
			gs->direct_resolver->timeout.m1.cnx = val;
			return GS_OK;
		case GS_TO_M1_OP:
			gs->direct_resolver->timeout.m1.op = val;
			return GS_OK;
		case GS_TO_M2_CNX:
			gs->timeout.m2.cnx = val;
			return GS_OK;
		case GS_TO_M2_OP:
			gs->timeout.m2.op = val;
			return GS_OK;
		case GS_TO_MCD_CNX:
			gs->metacd_resolver->timeout.cnx = val;
			return GS_OK;
		case GS_TO_MCD_OP:
			gs->metacd_resolver->timeout.op = val;
			return GS_OK;
		}
	}

	GSERRORSET(err, "<%s> invalid time_out type : %d", __FUNCTION__, to);
	return GS_ERROR;
}


int
gs_grid_storage_get_timeout(gs_grid_storage_t * gs, gs_timeout_t to)
{
	if (!gs) {
		WARN("invalid parameter (%s)", "no client");
		return -1;
	}
	if ((int)to < (int)GS_TO_RAWX_CNX || to > GS_TO_MCD_OP) {
		WARN("invalid parameter (%s)", "bad timeout");
		return -1;
	}
	if (!gs->direct_resolver || !gs->metacd_resolver) {
		WARN("invalid parameter (%s)", "bad client");
		return -1;
	}

	switch (to) {
	case GS_TO_RAWX_CNX:
		return gs->timeout.rawx.cnx;
	case GS_TO_RAWX_OP:
		return gs->timeout.rawx.op;
	case GS_TO_M0_CNX:
		return gs->direct_resolver->timeout.m0.cnx;
	case GS_TO_M0_OP:
		return gs->direct_resolver->timeout.m0.op;
	case GS_TO_M1_CNX:
		return gs->direct_resolver->timeout.m1.cnx;
	case GS_TO_M1_OP:
		return gs->direct_resolver->timeout.m1.op;
	case GS_TO_M2_CNX:
		return gs->timeout.m2.cnx;
	case GS_TO_M2_OP:
		return gs->timeout.m2.op;
	case GS_TO_MCD_CNX:
		return gs->metacd_resolver->timeout.cnx;
	case GS_TO_MCD_OP:
		return gs->metacd_resolver->timeout.op;
	}

	WARN("No such timeout value '%d'", to);
	return -1;
}

static gs_status_t
gs_manage_container_error_not_closed(gs_container_t * container,
		const char *caller, guint line, GError ** err)
{
	gint code;

	if (!err)
		return GS_ERROR;
	if (!*err)
		return GS_OK;

	code = (*err)->code;

	if (CODE_RETRY_CONTAINER(code))
		return GS_OK;

	gs_container_close_cnx(container);

	/*if it is a network error, only a container decache is necessary */
	if (CODE_RECONNECT_CONTAINER(code)) {
		if (!gs_container_reconnect(container, err)) {
			GSETERROR(err, "[from %s:%d] refresh error for %s/%s", caller, line,
					C0_NAME(container), C0_IDSTR(container));
			return GS_ERROR;
		}
		else
			return GS_OK;
	}

	/*full decache wanted and a container refresh */
	if (CODE_REFRESH_META0(code)) {
		NOTICE("META0 REFRESH on %s", g_error_get_message(*err));
		gs_decache_all(container->info.gs);
		if (!gs_container_refresh(container, err)) {
			GSETERROR(err, "[from %s:%d] refresh/reconnect error for %s/%s",
					caller, line, C0_NAME(container), C0_IDSTR(container));
			return GS_ERROR;
		}
		else
			return GS_OK;
	}

	if (CODE_REFRESH_CONTAINER(code)) {
		if (!gs_container_refresh(container, err)) {
			GSETERROR(err, "[from %s:%d] refresh/reconnect error for %s/%s",
					caller, line, C0_NAME(container), C0_IDSTR(container));
			return GS_ERROR;
		}
		else
			return GS_OK;
	}

#ifdef HAVE_ANNOYING_DEBUG_TRACES
	GSETERROR(err, "[from %s:%d] error not manageable for %s/%s", caller, line,
			C0_NAME(container), C0_IDSTR(container));
#endif
	return GS_ERROR;
	//return GS_OK;
}

gs_status_t
gs_manage_container_error(gs_container_t * container, const char *caller, guint line, GError ** err)
{
	if (!err || !*err) {
		GSETERROR(err, "[from %s] unknown error on %s/%s", caller,
			 C0_NAME(container), C0_IDSTR(container));
		return GS_ERROR;
	}

	TRACE("[from %s:%d] an error occured, %s/%s will be refreshed; cause:\r\n\t%s",
		caller, line, C0_NAME(container), C0_IDSTR(container), g_error_get_message(*err));

	/*if closed, we try to re-open it */
	if ((*err)->code == CODE_CONTAINER_CLOSED)
		WARN("Container closed : this should never happen");

	return gs_manage_container_error_not_closed(container, caller, line, err);
}

