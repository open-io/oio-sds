/*
OpenIO SDS core library
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

#ifndef OIO_SDS__core__oiocs_h
# define OIO_SDS__core__oiocs_h 1
# include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif

struct oio_cs_registration_s {
	const char *id;
	const char *url;
	const char * const * kv_tags;
};

/* -------------------------------------------------------------------------- */

struct oio_cs_client_s;

void oio_cs_client__destroy (struct oio_cs_client_s *self);

GError * oio_cs_client__register_service (struct oio_cs_client_s *self,
		const char *in_type, const struct oio_cs_registration_s *reg);

GError * oio_cs_client__lock_service (struct oio_cs_client_s *self,
		const char *in_type, const struct oio_cs_registration_s *reg,
		int score);

GError * oio_cs_client__unlock_service (struct oio_cs_client_s *self,
		const char *in_type, const struct oio_cs_registration_s *reg);

GError * oio_cs_client__deregister_service (struct oio_cs_client_s *self,
		const char *in_type, const struct oio_cs_registration_s *reg);

GError * oio_cs_client__flush_services (struct oio_cs_client_s *self,
		const char *in_type);

GError * oio_cs_client__list_services (struct oio_cs_client_s *self,
		const char *in_type, gboolean full,
		void (*on_reg) (const struct oio_cs_registration_s *reg, int score));

GError * oio_cs_client__list_types (struct oio_cs_client_s *self,
		void (*on_type) (const char *srvtype));

/* -------------------------------------------------------------------------- */

struct oio_cs_client_s * oio_cs_client__create_proxied (const char *ns);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__oiocs_h*/
