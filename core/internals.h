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

#ifndef OIO_SDS__core__internals_h
# define OIO_SDS__core__internals_h 1

#ifdef __cplusplus
extern "C" {
#endif

extern volatile int oio_sds_no_shuffle;

struct oio_cfg_handle_s;

struct oio_cfg_handle_vtable_s
{
	void (*clean) (struct oio_cfg_handle_s *self);
	gchar** (*namespaces) (struct oio_cfg_handle_s *self);
	gchar* (*get) (struct oio_cfg_handle_s *self, const char *ns, const char *k);
};

struct oio_cfg_handle_abstract_s
{
	struct oio_cfg_handle_vtable_s *vtable;
};

/* wraps self->clean() */
void oio_cfg_handle_clean (struct oio_cfg_handle_s *self);

/* wraps self->namespaces() */
gchar ** oio_cfg_handle_namespaces (struct oio_cfg_handle_s *self);

/* wraps self->get(ns, k) */
gchar * oio_cfg_handle_get (struct oio_cfg_handle_s *self,
		const char *ns, const char *k);

/* Replaces the default handle to manage configuration by yourself. */
void oio_cfg_set_handle (struct oio_cfg_handle_s *self);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__core__internals_h*/
