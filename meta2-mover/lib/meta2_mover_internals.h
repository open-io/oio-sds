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

#ifndef GS_META2_MOVER__H
# define GS_META2_MOVER__H 1
# ifdef HAVE_CONFIG_H
#  include <config.h>
# endif /* HAVE_CONFIG_H */
# ifndef LOG_DOMAIN
#  define LOG_DOMAIN "grid.meta2.mover"
# endif
# include <stdlib.h>
# include <string.h>
# include <errno.h>
# include <glib.h>
# include <metatypes.h>
# include <metautils.h>
# include <metacomm.h>
# define GS_ERROR_NEW(CODE,FMT,...) g_error_new(g_quark_from_static_string(LOG_DOMAIN), CODE, FMT, ##__VA_ARGS__)
# define GS_ERROR_STACK(E) g_prefix_error((E), "from(%s:%d,%s) ", __FILE__, __LINE__, __FUNCTION__)

struct xcid_s {
	container_id_t cid;
	gchar str[STRLEN_CONTAINERID];
	struct gs_container_location_s *location;
};

struct xaddr_s {
	addr_info_t addr;
	gchar str[STRLEN_ADDRINFO];
	struct metacnx_ctx_s cnx;
};

/* Utils features --------------------------------------------------------- */

GError* xaddr_init_from_addr(struct xaddr_s *x, const addr_info_t *ai);

GError* xaddr_init_from_url(struct xaddr_s *x, const gchar *url);

struct xcid_s * xcid_from_hexa(const gchar *h);

void xcid_free(struct xcid_s *x);

/* Load-Balancing features ------------------------------------------------- */

extern time_t interval_update_services;

const service_info_t* get_available_meta2_from_conscience(const gchar * ns_name, const addr_info_t *avoid);

void meta2_mover_clean_services(void);

gboolean meta2_mover_srv_is_source(addr_info_t *ai);

const gchar* meta2_mover_get_ns(void);

#endif /* GS_META2_MOVER__H */
