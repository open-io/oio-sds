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

#ifndef GRID__UTILS_INTERNALS__H
# define GRID__UTILS_INTERNALS__H 1

/**
 * @defgroup server_misc Misc. features
 * @ingroup server
 * @brief
 * @details
 *
 * @{
 */

#include <metautils.h>

# ifdef HAVE_ASSERT_SERVER
#  define SERVER_ASSERT(X) g_assert(X)
# else
#  define SERVER_ASSERT(X)
# endif

# ifdef HAVE_ASSERT_HTTP
#  define HTTP_ASSERT(X) g_assert(X)
# else
#  define HTTP_ASSERT(X)
# endif

# ifndef GRID_STAT_PREFIX_REQ
#  define GRID_STAT_PREFIX_REQ "gridd.counter.req"
# endif

# ifndef GRID_STAT_PREFIX_TIME
#  define GRID_STAT_PREFIX_TIME "gridd.counter.time"
# endif

# ifndef HTTP_STAT_PREFIX_REQ
#  define HTTP_STAT_PREFIX_REQ "http.counter.req"
# endif

# ifndef HTTP_STAT_PREFIX_TIME
#  define HTTP_STAT_PREFIX_TIME "http.counter.time"
# endif

#ifndef SERVER_DEFAULT_MAX_IDLEDELAY
# define SERVER_DEFAULT_MAX_IDLEDELAY 300
#endif

#ifndef SERVER_DEFAULT_MAX_WORKERS
# define SERVER_DEFAULT_MAX_WORKERS 200
#endif

static inline guint64
guint_to_guint64(guint u)
{
	guint64 u64 = u;
	return u64;
}

/** @} */

#endif /* GRID__UTILS_INTERNALS__H */
