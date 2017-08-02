/*
OpenIO SDS oio-event-benchmark
Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__tools__benchmark_event__fake_service_h
#define OIO_SDS__tools__benchmark_event__fake_service_h

#include <glib.h>

gboolean fake_service_configure(void);

gboolean fake_service_run(void);

void fake_service_stop(void);

void fake_service_too_long(void);

void fake_service_fini(void);

#endif /* OIO_SDS__tools__benchmark_event__fake_service_h */
