/*
OpenIO SDS metautils
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <metautils/metautils.h>

#include "srvset.h"

static struct service_info_s * _init (int port) {
	struct service_info_s *si = g_malloc0 (sizeof(*si));
	g_strlcpy(si->ns_name, "NS", sizeof(si->ns_name));
	g_strlcpy(si->type, NAME_SRVTYPE_META0, sizeof(si->type));
	grid_string_to_addrinfo ("127.0.0.1:6000", &si->addr);
	si->addr.port = g_htons(port);
	return si;
}

int main (int argc, char **argv) {
	(void) argc, (void) argv;

	srvset_t *ss = srvset_new ();
	srvset_purge (ss, (time_t)-1);
	g_assert (NULL == srvset_get (ss, "NOTFOUND"));
	g_assert (!srvset_has (ss, "NOTFOUND"));
	srvset_delete (ss, "NOTFOUND");

	struct service_info_s *si0 = _init(6000);
	gchar *k0 = service_info_key (si0);
	STRING_STACKIFY (k0);

	struct service_info_s *si1 = _init(6001);
	gchar *k1 = service_info_key (si1);
	STRING_STACKIFY (k1);

	srvset_push_and_clean (ss, si1);
	srvset_push_and_clean (ss, si0);

	g_assert (NULL == srvset_get (ss, "NOTFOUND"));
	g_assert (!srvset_has (ss, "NOTFOUND"));
	srvset_delete (ss, "NOTFOUND");

	g_assert (si0 == srvset_get (ss, k0));
	g_assert (srvset_has (ss, k0));
	srvset_delete (ss, k0);
	g_assert (NULL == srvset_get (ss, k0));
	g_assert (!srvset_has (ss, k0));

	srvset_run (ss, NULL, NULL);

	srvset_clean (ss);
	return 0;
}

