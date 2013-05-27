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

#ifndef HC_RESOLVER__INTERNALS__H
# define HC_RESOLVER__INTERNALS__H 1
# include <glib.h>
# include "./hc_resolver.h"
# include "../metautils/lib/hashstr.h"
# include "../metautils/lib/lrutree.h"

/**
 * 
 */
struct cached_element_s
{
	time_t ttl;
	time_t use;
	guint32 count_served;
	guint16 count_elements;
	gchar s[]; /* Must be the last! */
};

/**
 *
 */
struct hc_resolver_s
{
	guint max_elements;
	guint max_served;
	enum hc_resolver_flags_e flags;

	GMutex *lock;
	struct lru_tree_s *cache;
};

#endif /* HC_RESOLVER__INTERNALS__H */
