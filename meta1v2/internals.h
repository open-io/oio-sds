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

#ifndef META1__INTERNALS_H
# define META1__INTERNALS_H 1

/**
 * @addtogroup meta1v2_misc 
 * @{
 */

# include <metautils.h>
# include <metatypes.h>
# include <metacomm.h>

# ifdef HAVE_ASSERT_META1
#  define META1_ASSERT(X) g_assert(X)
# else
#  define META1_ASSERT(X)
# endif

#define CONNECT_RETRY_DELAY 10

/**
 * @param reqname
 * @param cid
 * @param err
 * @return
 */
MESSAGE meta1_create_message(const gchar *reqname, const container_id_t cid,
		GError **err);


/**
 * @param req
 * @param fname
 * @param addr
 * @param err
 * @return
 */
gboolean meta1_enheader_addr_list(MESSAGE req, const gchar *fname,
		GSList *addr, GError **err);

/** @} */

#endif
