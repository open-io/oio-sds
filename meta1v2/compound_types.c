/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#include <metautils/lib/metautils.h>

#include "./compound_types.h"

void
compound_type_clean(struct compound_type_s *ct)
{
	if (!ct)
		return;
}

GError*
compound_type_parse(struct compound_type_s *ct, const gchar *srvtype)
{
	EXTRA_ASSERT(ct != NULL);
	memset(ct, 0, sizeof(struct compound_type_s));

	if (!srvtype || !*srvtype || *srvtype == '.')
		return BADREQ("Bad service type [%s]", srvtype);

	if (strchr(srvtype, ';'))
		return BADREQ("No argument allowed on service type");

	ct->fulltype = srvtype;
	g_strlcpy(ct->type, srvtype, sizeof(ct->type));
	GRID_TRACE("CT full[%s] type[%s]", ct->fulltype, ct->type);
	return NULL;
}
