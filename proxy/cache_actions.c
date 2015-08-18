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

enum http_rc_e
action_cache_flush_all (struct req_args_s *args)
{
	grid_lbpool_flush (lbpool);
	hc_resolver_flush_csm0 (resolver);
	hc_resolver_flush_services (resolver);
	return _reply_success_json (args, NULL);
}

enum http_rc_e
action_cache_flush_low (struct req_args_s *args)
{
	hc_resolver_flush_services (resolver);
	return _reply_success_json (args, NULL);
}

enum http_rc_e
action_cache_flush_high (struct req_args_s *args)
{
	hc_resolver_flush_csm0 (resolver);
	return _reply_success_json (args, NULL);
}

enum http_rc_e
action_cache_set_max_high (struct req_args_s *args)
{
	hc_resolver_set_max_csm0 (resolver, atoi (TOK ("COUNT")));
	return _reply_success_json (args, NULL);
}

enum http_rc_e
action_cache_set_max_low (struct req_args_s *args)
{
	hc_resolver_set_max_services (resolver, atoi (TOK ("COUNT")));
	return _reply_success_json (args, NULL);
}

enum http_rc_e
action_cache_set_ttl_high (struct req_args_s *args)
{
	hc_resolver_set_ttl_csm0 (resolver, atoi (TOK ("COUNT")));
	return _reply_success_json (args, NULL);
}

enum http_rc_e
action_cache_set_ttl_low (struct req_args_s *args)
{
	hc_resolver_set_ttl_services (resolver, atoi (TOK ("COUNT")));
	return _reply_success_json (args, NULL);
}

enum http_rc_e
action_cache_status (struct req_args_s *args)
{
	struct hc_resolver_stats_s s;
	memset (&s, 0, sizeof (s));
	hc_resolver_info (resolver, &s);

	GString *gstr = g_string_new ("{");
	g_string_append_printf (gstr, " \"clock\":%lu,", s.clock);
	g_string_append_printf (gstr, " \"csm0\":{"
		"\"count\":%" G_GINT64_FORMAT ",\"max\":%u,\"ttl\":%lu},",
		s.csm0.count, s.csm0.max, s.csm0.ttl);
	g_string_append_printf (gstr, " \"meta1\":{"
		"\"count\":%" G_GINT64_FORMAT ",\"max\":%u,\"ttl\":%lu}",
		s.services.count, s.services.max, s.services.ttl);
	g_string_append_c (gstr, '}');
	return _reply_success_json (args, gstr);
}
