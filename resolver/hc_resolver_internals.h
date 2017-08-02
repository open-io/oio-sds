/*
OpenIO SDS resolver
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

#ifndef OIO_SDS__resolver__hc_resolver_internals_h
# define OIO_SDS__resolver__hc_resolver_internals_h 1

# include <resolver/hc_resolver.h>
# include <glib.h>

struct lru_tree_s;

struct cached_element_s
{
	guint32 count_elements;
	gchar s[]; /* Must be the last! */
};

struct lru_ext_s
{
	struct lru_tree_s *cache;
	gint64 ttl;
	guint max;
};

struct hc_resolver_s
{
	GMutex lock;
	struct lru_ext_s services;
	struct lru_ext_s csm0;
	enum hc_resolver_flags_e flags;

	/* called with the IP:PORT string */
	gboolean (*service_qualifier) (gconstpointer);

	/* called with the IP:PORT string */
	void (*service_notifier) (gconstpointer);
};

#endif /*OIO_SDS__resolver__hc_resolver_internals_h*/
