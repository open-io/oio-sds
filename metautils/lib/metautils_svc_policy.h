/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__metautils__lib__metautils_svc_policy_h
# define OIO_SDS__metautils__lib__metautils_svc_policy_h 1

# include <glib.h>

struct hashstr_s;

struct service_update_policies_s;

/* Tells how to update a service in place */
enum service_update_policy_e
{
	SVCUPD_KEEP = 1, /*!< do not touch services in place */
	SVCUPD_APPEND,   /*!< keep down services, append a new if all are down */
	SVCUPD_REPLACE   /*!< Replace the last service down is none is up */
};

const char * service_update_policy_to_string (enum service_update_policy_e p);

struct service_update_policies_s* service_update_policies_create(void);

void service_update_policies_destroy(struct service_update_policies_s *pol);

gboolean service_update_tagfilter2(struct service_update_policies_s *pol,
		const struct hashstr_s *htype, gchar **pname, gchar **pvalue);

gboolean service_update_tagfilter(struct service_update_policies_s *pol,
		const gchar *type, gchar **pname, gchar **pvalue);

/** Get the value associated with the tag defined for the policy (or NULL). */
gchar * service_update_get_tag_value(struct service_update_policies_s *pol,
		const gchar *type, gchar *tag_key);

enum service_update_policy_e service_howto_update(
		struct service_update_policies_s *pol,
		const gchar *type);

/* @return 0 if unspecified, or the number of expected replicas */
guint service_howmany_replicas(
		struct service_update_policies_s *pol,
		const gchar *type);

/* @return 0 if unspecified, or the expected distance */
guint service_howmany_distance(
		struct service_update_policies_s *pol,
		const gchar *type);

GError* service_update_reconfigure(struct service_update_policies_s *pol,
		const gchar *cfg);

gchar* service_update_policies_dump(struct service_update_policies_s *pol);

#endif /*OIO_SDS__metautils__lib__metautils_svc_policy_h*/
