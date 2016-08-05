/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__cluster__conscience__conscience_srv_h
# define OIO_SDS__cluster__conscience__conscience_srv_h 1

# include <metautils/lib/metatypes.h>
# include <cluster/conscience/conscience_srvtype.h>

# ifndef LIMIT_LENGTH_SRVDESCR
#  define LIMIT_LENGTH_SRVDESCR LIMIT_LENGTH_NSNAME + LIMIT_LENGTH_SRVTYPE + STRLEN_ADDRINFO
# endif

struct conscience_srvid_s
{
	addr_info_t addr;
};

struct conscience_srv_s
{
	struct conscience_srvid_s id;
	struct conscience_srvtype_s *srvtype;
	gchar description[LIMIT_LENGTH_SRVDESCR];
	score_t score;
	gboolean locked;
	GPtrArray *tags;
	time_t  time_last_alert;

	/*Allow a user to associate user data*/
	enum { SAD_NONE=0, SAD_REAL, SAD_UINT, SAD_INT, SAD_PTR } app_data_type;
	union {
		gdouble r;
		guint64 u64;
		gint64  i64;
		struct {
			gpointer value;
			GDestroyNotify cleaner;
		} pointer;
	} app_data;

	/*a ring by service type */
	struct conscience_srv_s *next;
	struct conscience_srv_s *prev;
};

void conscience_srv_destroy(struct conscience_srv_s *service);

score_t* conscience_srv_compute_score(struct conscience_srv_s *service,
    GError ** err);

struct service_tag_s *conscience_srv_get_tag(struct
    conscience_srv_s *srv, const gchar * name);

struct service_tag_s *conscience_srv_ensure_tag(struct
    conscience_srv_s *srv, const gchar * name);

void conscience_srv_fill_srvinfo( struct service_info_s *dst,
		struct conscience_srv_s *src);

void conscience_srv_fill_srvinfo_header( struct service_info_s *dst,
		struct conscience_srv_s *src);

static inline void
service_ring_remove(struct conscience_srv_s *service)
{
	if (service->prev)
		service->prev->next = service->next;
	if (service->next)
		service->next->prev = service->prev;
}

#endif /*OIO_SDS__cluster__conscience__conscience_srv_h*/
