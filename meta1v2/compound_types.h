/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__meta1v2__compound_types_h
# define OIO_SDS__meta1v2__compound_types_h 1

#include <glib.h>
#include <metautils/lib/metatypes.h>

struct service_update_policies_s;

struct compound_type_s
{
	const gchar *fulltype;
	gchar type[LIMIT_LENGTH_SRVTYPE]; // type without args
};

// Calls g_free on each non NULL field of the structure.
void compound_type_clean(struct compound_type_s *ct);

// Parses the configuration string.
// In case of error, the fields of CT are cleaned.
// Before starting to work, the structure is blanked (i.e. not cleaned
// with compound_type_clean().
// format: TYPE[.SUBTYPE][;ARGS]
GError* compound_type_parse(struct compound_type_s *ct, const gchar *srvtype);

#endif /*OIO_SDS__meta1v2__compound_types_h*/
