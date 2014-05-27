#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m2v2.utils.lb"
#endif

#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_utils_lb.h>

#include <glib.h>

GError*
service_info_from_chunk_id(struct grid_lbpool_s *glp,
		const gchar *chunk_id, service_info_t **srvinfo)
{
	GError *err = NULL;
	struct service_info_s *si = NULL;

	if (chunk_id == NULL || strlen(chunk_id) <= 0)
		return NEWERROR(CODE_INTERNAL_ERROR, "emtpy chunk id");

	// TODO FIXME Factorizes this with client/c/lib/loc_context.c and
	// TODO FIXME meta2v2/meta2_utils_lb.c, rawx-mover/src/main.c
	char **tok = g_regex_split_simple(
			"(([[:digit:]]{1,3}\\.){3}[[:digit:]]{1,3}:[[:digit:]]{1,5})",
			chunk_id, 0, 0);
	if (!tok || g_strv_length(tok) < 3)
		err = NEWERROR(CODE_INTERNAL_ERROR, "could not parse chunk id");

	if (err == NULL) {
		si = grid_lbpool_get_service_from_url(glp, "rawx", tok[1]);
		if (si == NULL)
			err = NEWERROR(CODE_INTERNAL_ERROR,
					"unable to find service info from %s", tok[1]);
		else
			*srvinfo = si;
	}

	g_strfreev(tok);
	return err;
}

//------------------------------------------------------------------------------

// TODO: export?
static gpointer
_gen_chunk_info(struct service_info_s *si)
{
	chunk_info_t *ci = g_malloc0(sizeof(chunk_info_t));
	SHA256_randomized_buffer(ci->id.id, sizeof(ci->id.id));
	memcpy(&(ci->id.addr), &(si->addr), sizeof(addr_info_t));
	g_strlcpy(ci->id.vol,
		service_info_get_tag_value(si, NAME_TAGNAME_RAWX_VOL, "/"),
		LIMIT_LENGTH_VOLUMENAME);
	ci->size = 0;
	ci->position = 0;
	ci->nb = 0;

	return (gpointer)ci;
}

// TODO: export?
static gpointer
_gen_chunk_bean(struct service_info_s *si)
{
	gchar straddr[STRLEN_ADDRINFO], strid[STRLEN_CHUNKID];
	gchar *strvol = NULL;
	gchar *chunk_id = NULL;
	struct bean_CHUNKS_s *chunk = NULL;

	grid_addrinfo_to_string(&(si->addr), straddr, sizeof(straddr));
	SHA256_randomized_string(strid, sizeof(strid));
	strvol = metautils_rawx_get_volume(si);
	chunk = _bean_create(&descr_struct_CHUNKS);
	chunk_id = assemble_chunk_id(straddr, strvol, strid);
	CHUNKS_set2_id(chunk, chunk_id);

	g_free(strvol);
	g_free(chunk_id);
	return (gpointer)chunk;
}

//------------------------------------------------------------------------------


static GError*
_poll_services(struct grid_lbpool_s *lbp, const gchar *srvtype,
		struct lb_next_opt_ext_s *opt_ext,
		GSList **result, gboolean use_beans)
{
	struct grid_lb_iterator_s *iter = NULL;
	struct service_info_s **psi, **siv = NULL;

	if (!lbp || !srvtype)
		return NEWERROR(500, "Invalid parameter");
	if (!(iter = grid_lbpool_get_iterator(lbp, srvtype)))
		return NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "No RAWX available");


	if (!grid_lb_iterator_next_set2(iter, &siv, opt_ext))
		return NEWERROR(CODE_PLATFORM_ERROR, "Cannot get services"
				" list for the specified storage policy");

	if (use_beans) {
		for(psi=siv; *psi; ++psi)
			*result = g_slist_prepend(*result, _gen_chunk_bean(*psi));
	}
	else {
		for(psi=siv; *psi; ++psi)
			*result = g_slist_prepend(*result, _gen_chunk_info(*psi));
	}

	service_info_cleanv(siv, FALSE);
	return NULL;
}

GError*
get_spare_chunks(struct grid_lbpool_s *lbp, struct storage_policy_s *stgpol,
		GSList **result, gboolean use_beans)
{
	const char *k, *m, *cpstr, *diststr;
	const struct data_security_s *ds = storage_policy_get_data_security(stgpol);
	struct lb_next_opt_ext_s opt_ext;

	memset(&opt_ext, 0, sizeof(opt_ext));
	opt_ext.req.stgclass = storage_policy_get_storage_class(stgpol);
	opt_ext.req.strict_stgclass = TRUE;

	diststr = data_security_get_param(ds, DS_KEY_DISTANCE);
	opt_ext.req.distance = (NULL != diststr) ? atoi(diststr) : 1;

	switch (data_security_get_type(ds)) {
		case RAIN:
			k = data_security_get_param(ds, DS_KEY_K);
			m = data_security_get_param(ds, DS_KEY_M);
			if (!k || !m)
				return NEWERROR(400, "Invalid RAIN policy (missing K and/or M)");
			opt_ext.req.max = atoi(k) + atoi(m);
			break;
		case DUPLI:
			cpstr = data_security_get_param(ds, DS_KEY_COPY_COUNT);
			opt_ext.req.max = (NULL != cpstr) ? atoi(cpstr) : 1;
			break;
		case DS_NONE:
			opt_ext.req.max = 1;
			break;
		default:
			return NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy type");
	}

	return _poll_services(lbp, "rawx", &opt_ext, result, use_beans);
}

//------------------------------------------------------------------------------

GError*
get_conditioned_spare_chunks(struct grid_lbpool_s *lbp,
		gint64 count, gint64 dist, const struct storage_class_s *stgclass,
		GSList *notin, GSList *broken,
		GSList **result, gboolean answer_beans)
{
	struct lb_next_opt_ext_s opt_ext;
	memset(&opt_ext, 0, sizeof(opt_ext));
	opt_ext.req.max = count;
	opt_ext.req.distance = dist;
	opt_ext.req.duplicates = (dist <= 0);
	opt_ext.req.stgclass = stgclass;
	opt_ext.req.strict_stgclass = FALSE;
	opt_ext.srv_inplace = notin;
	opt_ext.srv_forbidden = broken;

	return _poll_services(lbp, "rawx", &opt_ext, result, answer_beans);
}

static GSList *
convert_chunks_to_srvinfo(struct grid_lbpool_s *lbp, GSList *src)
{
	GSList *result = NULL;

	for (GSList *l=src; l ;l=l->next) {
		if (!l->data || DESCR(l->data) != &descr_struct_CHUNKS)
			continue;

		struct service_info_s *si = NULL;
		GError *e = service_info_from_chunk_id(lbp, CHUNKS_get_id(l->data)->str, &si);
		if (NULL != e) {
			GRID_WARN("CHUNK -> ServiceInfo conversion error : (%d) %s",
					e->code, e->message);
			g_clear_error(&e);
			continue;
		}
		result = g_slist_prepend(result, si);
	}

	return result;
}

GError*
get_conditioned_spare_chunks2(struct grid_lbpool_s *lbp,
		struct storage_policy_s *stgpol,
		GSList *already, GSList *broken,
		GSList **result, gboolean answer_beans)
{
	const struct data_security_s *ds = storage_policy_get_data_security(stgpol);
	const struct storage_class_s *stgclass = storage_policy_get_storage_class(stgpol);

	struct lb_next_opt_ext_s opt_ext;
	memset(&opt_ext, 0, sizeof(opt_ext));
	opt_ext.req.max = 0;
	opt_ext.req.distance = data_security_get_int64_param(ds, DS_KEY_DISTANCE, 0);
	opt_ext.req.duplicates = (opt_ext.req.distance <= 0);
	opt_ext.req.stgclass = stgclass;
	opt_ext.req.strict_stgclass = FALSE;
	opt_ext.srv_inplace = NULL;
	opt_ext.srv_forbidden = NULL;

	switch (data_security_get_type(ds)) {
		case DUPLI:
			opt_ext.req.max = data_security_get_int64_param(ds, DS_KEY_COPY_COUNT, 1);
			break;
		case RAIN:
			opt_ext.req.max = data_security_get_int64_param(ds, DS_KEY_K, 1)
				+ data_security_get_int64_param(ds, DS_KEY_M, 0);
			break;
		case DS_NONE:
			opt_ext.req.max = 1;
			break;
		default:
			return NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid storage policy");
	}

	guint count = g_slist_length(already);
	if (opt_ext.req.max > count)
		opt_ext.req.max = opt_ext.req.max - count;
	else
		opt_ext.req.max = 1;

	GError *err = NULL;

	opt_ext.srv_forbidden = convert_chunks_to_srvinfo(lbp, broken);
	opt_ext.srv_inplace = convert_chunks_to_srvinfo(lbp, already);
	err = _poll_services(lbp, "rawx", &opt_ext, result, answer_beans);
	g_slist_free_full(opt_ext.srv_forbidden, (GDestroyNotify)service_info_clean);
	g_slist_free_full(opt_ext.srv_inplace, (GDestroyNotify)service_info_clean);

	return err;
}

