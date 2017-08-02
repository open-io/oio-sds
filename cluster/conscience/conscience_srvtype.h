/*
OpenIO SDS cluster conscience
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

#ifndef OIO_SDS__cluster__conscience__conscience_srvtype_h
# define OIO_SDS__cluster__conscience__conscience_srvtype_h 1

# include <metautils/lib/metautils.h>
# include <cluster/conscience/conscience_srv.h>

struct conscience_srvtype_s
{
	GStaticRWLock rw_lock;
	struct conscience_s *conscience;
	gchar type_name[LIMIT_LENGTH_SRVTYPE];

	time_t alert_frequency_limit;
	time_t score_expiration;
	gint32 score_variation_bound;
	gchar *score_expr_str;
	struct expr_s *score_expr;
	gboolean lock_at_first_register;

	GHashTable *config_ht;	 /**<Maps (gchar*) to (GByteArray*)*/
	GByteArray *config_serialized;	/**<Preserialized configuration sent to the agents*/

	GHashTable *services_ht;	     /**<Maps (conscience_srvid_s*) to (conscience_srv_s*)*/
	struct conscience_srv_s services_ring;
};

typedef gboolean (service_callback_f) (struct conscience_srv_s * srv, gpointer udata);

struct conscience_srvtype_s *conscience_srvtype_create(struct conscience_s *conscience, const char *type);

void conscience_srvtype_destroy(struct conscience_srvtype_s *srvtype);

gboolean conscience_srvtype_set_type_expression(struct conscience_srvtype_s
    *srvtype, GError ** error, const gchar * expr_str);

void conscience_srvtype_flush(struct conscience_srvtype_s *srvtype);

struct conscience_srv_s *conscience_srvtype_register_srv(struct
    conscience_srvtype_s *srvtype, GError ** err, const struct conscience_srvid_s *srvid);

struct conscience_srv_s * conscience_srvtype_refresh(
		struct conscience_srvtype_s *srvtype, struct service_info_s *srvinfo);

guint conscience_srvtype_zero_expired(struct conscience_srvtype_s *srvtype,
		service_callback_f * callback, gpointer udata);

gboolean conscience_srvtype_run_all(struct conscience_srvtype_s *srvtype,
    GError ** error, guint32 flags, service_callback_f * callback, gpointer udata);

struct conscience_srv_s *conscience_srvtype_get_srv(struct
    conscience_srvtype_s *srvtype, const struct conscience_srvid_s *srvid);

void conscience_srvtype_remove_srv(struct conscience_srvtype_s *srvtype, struct conscience_srvid_s *srvid);

void conscience_srvtype_init(struct conscience_srvtype_s *srvtype);

#endif /*OIO_SDS__cluster__conscience__conscience_srvtype_h*/
