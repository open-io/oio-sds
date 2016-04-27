/*
OpenIO SDS proxy
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "common.h"
#include "actions.h"

static GError *
_lb_check_tokens (struct req_args_s *args)
{
	if (!validate_namespace(NS()))
		return NEWERROR(CODE_NAMESPACE_NOTMANAGED, "Invalid NS");
	if (POOL() && !validate_srvtype(POOL()))
		return NEWERROR(CODE_NAMESPACE_NOTMANAGED, "Invalid POOL");
	return NULL;
}

// New handlers ----------------------------------------------------------------

static GString *
_lb_pack_and_free_srvinfo_tab (struct service_info_s **siv)
{
	GString *gstr = g_string_sized_new (512);
	g_string_append_c(gstr, '[');
	for (struct service_info_s **pp = siv; *pp ;pp++) {
		if (siv != pp)
			g_string_append_c(gstr, ',');
		service_info_encode_json(gstr, *pp, FALSE);
	}
	g_string_append_c(gstr, ']');
	return gstr;
}

static enum http_rc_e
_lb (struct req_args_s *args, struct grid_lb_iterator_s *iter)
{
	const char *tagk, *tagv, *cls, *sz;
	gboolean _filter_tag (struct service_info_s *si, gpointer u) {
		(void)u;
		if (!tagk)
			return TRUE;
		if (!si || !si->tags)
			return FALSE;

		struct service_tag_s *tag = service_info_get_tag(si->tags, tagk);
		if (!tag)
			return FALSE;
		if (!tagv) // No value specified, the presence is enough
			return TRUE;

		gchar tmp[128];
		service_tag_to_string(tag, tmp, sizeof(tmp));
		return 0 == strcmp(tmp, tagv);
	}

	if (!iter)
		return _reply_system_error (args, NEWERROR (
					CODE_SRVTYPE_NOTMANAGED, "Type not managed"));

	tagk = OPT("tagk");
	tagv = OPT("tagv");
	cls = OPT("stgcls");
	sz = OPT("size");

	// Terribly configurable and poorly implemented LB
	struct storage_class_s *stgcls = storage_class_init(&nsinfo, cls);
	struct lb_next_opt_ext_s opt;
	opt.req.distance = 1;
	opt.req.max = sz ? atoi(sz) : 1;
	opt.req.duplicates = FALSE;
	opt.req.stgclass = !stgcls ? NULL : stgcls;
	opt.req.strict_stgclass = FALSE;
	opt.filter.data = NULL;
	opt.filter.hook = tagk ? _filter_tag : NULL;
	opt.srv_inplace = NULL;
	opt.srv_forbidden = NULL;

	GError *err = NULL;
	struct service_info_s **siv = NULL;
	gboolean rc = grid_lb_iterator_next_set2(iter, &siv, &opt, &err);
	if (stgcls)
		storage_class_clean(stgcls);

	if (!rc) {
		service_info_cleanv(siv, FALSE);
		g_prefix_error(&err, "Too constrained: ");
		return _reply_system_error (args, err);
	} else {
		GString *gstr = _lb_pack_and_free_srvinfo_tab (siv);
		service_info_cleanv (siv, FALSE);
		return _reply_success_json (args, gstr);
	}
}

enum http_rc_e
action_lb_choose (struct req_args_s *args)
{
	GError *err;
	args->rp->no_access();
	if (NULL != (err = _lb_check_tokens(args)))
		return _reply_notfound_error (args, err);
	return _lb (args, grid_lbpool_ensure_iterator(lbpool, POOL()));
}
