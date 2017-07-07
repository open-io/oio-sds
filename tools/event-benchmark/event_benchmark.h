/*
OpenIO SDS oio-event-benchmark
Copyright (C) 2017 OpenIO, as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__tools__benchmark_event__event_benchmark_h
#define OIO_SDS__tools__benchmark_event__event_benchmark_h

#define RAWX_ADDRESS "127.0.0.1:4444"
#define FAKE_SERVICE_ADDRESS "127.0.0.1:4445"

enum event_type_e {
	CHUNK_NEW,
	CHUNK_DELETED,
	CONTAINER_NEW,
	CONTAINER_STATE,
	CONTAINER_DELETED,
	CONTENT_DELETED,
};

#endif /* OIO_SDS__tools__benchmark_event__event_benchmark_h */
