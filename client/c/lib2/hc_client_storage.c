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

#include "./hc_client_internals.h"

GError*
_meta2v2_action(struct hc_client_s *hc, struct hc_url_s *u,
		GError* (*action)(gchar **))
{
	GError *err = NULL;
	gchar **targets = NULL;

	g_assert(hc != NULL);
	g_assert(u != NULL);

	if (!hc_url_has(u, HCURL_NS) || !hc_url_has(u, HCURL_REFERENCE))
		return g_error_new(GQ(), 400, "Bad url");

	err = hc_resolve_reference_service(hc->resolver, u, "meta2", &targets);
	if (err != NULL) {
		ASSERT_EXTRA(targets == NULL);
		g_prefix_error(&err, "Resolver error: ");
		return err;
	}
	if (!targets || !*targets) {
		err = g_error_new(GQ(), CODE_CONTAINER_NOTFOUND, "No meta2 found");
		if (targets)
			g_strfreev(targets);
		return err;
	}

	err = action(targets);
	g_strfreev(targets);
	return err;
}

struct hc_client_s*
hc_client_create(struct hc_resolver_s *resolver)
{
	struct hc_client_s *result;
	g_assert(resolver != NULL);
	result = g_malloc0(sizeof(*result));
	result->resolver = resolver;
	return result;
}

void
hc_client_destroy(struct hc_client_s *client)
{
	if (client) {
		g_free(client);
	}
}

GError*
hc_client_storage_delete_url(struct hc_client_s *hc, struct hc_url_s *u)
{
	GError* _action(gchar **targets) {
		GError *err;
		GSList *beans = NULL;

		if (!(err = m2v2_remote_execute_DEL(targets[0], NULL, u, &beans))) {
			_bean_cleanl2(beans);
			return NULL;
		}

		ASSERT_EXTRA(beans == NULL);
		g_prefix_error(&err, "Request error: ");
		return err;
	}

	return _meta2v2_action(hc, u, _action);
}

GError*
hc_client_storage_has_url(struct hc_client_s *hc, struct hc_url_s *u)
{
	GError* _action(gchar **targets) {
		GError *err;
		GSList *beans = NULL;

		if (!(err = m2v2_remote_execute_HAS(targets[0], NULL, u)))
			return NULL;

		ASSERT_EXTRA(beans == NULL);
		g_prefix_error(&err, "Request error: ");
		return err;
	}

	return _meta2v2_action(hc, u, _action);
}

GError*
hc_client_storage_list_url(struct hc_client_s *hc, struct hc_url_s *u, GSList **result)
{
	if(!hc || !u || !result)
		return g_error_new(GQ(), 400, "invalid parameter");
	
	GError* _action(gchar **targets) {
		GError *err;

		if (!(err = m2v2_remote_execute_LIST(targets[0], NULL, u, M2V2_FLAG_ALLVERSION, result)))
			return NULL;

		return err;
	}

	return _meta2v2_action(hc, u, _action);
}

