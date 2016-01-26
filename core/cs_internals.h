/*
OpenIO SDS core library
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__sdk__cs_internals_h
# define OIO_SDS__sdk__cs_internals_h 1
#ifdef __cplusplus
extern "C" {
#endif

struct oio_cs_client_s;
struct oio_cs_registration_s;

struct oio_cs_client_vtable_s
{
	void (*destroy) (struct oio_cs_client_s *self);

	GError * (*register_service) (struct oio_cs_client_s *self,
			const char *in_type, const struct oio_cs_registration_s *reg);

	GError * (*lock_service) (struct oio_cs_client_s *self,
			const char *in_type, const struct oio_cs_registration_s *reg,
			int scor);

	GError * (*deregister_service) (struct oio_cs_client_s *self,
			const char *in_type, const char *id);

	GError * (*flush_services) (struct oio_cs_client_s *self,
			const char *in_type);

	GError * (*unlock_service) (struct oio_cs_client_s *self,
			const char *in_type, const char *id);

	GError * (*list_services) (struct oio_cs_client_s *self,
			const char *in_type,
			void (*on_reg) (const struct oio_cs_registration_s *reg, int score));

	GError * (*list_types) (struct oio_cs_client_s *self,
			void (*on_type) (const char *srvtype));
};

struct oio_cs_client_abstract_s
{
	struct oio_cs_client_vtable_s *vtable;
};

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__sdk__cs_internals_h*/
