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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "client"
#endif

#include "../../../metautils/lib/metacomm.h"
#include "../../../metautils/lib/metautils.h"
#include "../../../metautils/lib/hc_url.h"
#include "../../../resolver/hc_resolver.h"
#include "../../../meta2v2/meta2v2_remote.h"
#include "../../../meta2v2/meta2_utils.h"
#include "../../../meta2v2/generic.h"
#include "./hc_client_storage.h"

struct hc_client_s
{
	struct hc_resolver_s *resolver;
};

GError* _meta2v2_action(struct hc_client_s *hc, struct hc_url_s *u,
		GError* (*action)(gchar **));

