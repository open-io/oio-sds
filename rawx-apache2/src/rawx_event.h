/*
OpenIO SDS rawx-apache2
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

#ifndef OIO_SDS__rawx_apache2__src__rawx_event_h
# define OIO_SDS__rawx_apache2__src__rawx_event_h 1

#define RAWX_EVENT_ADDR_SIZE 256

/**
 * Initialize event mechanism
 *
 * @addr event agent address or NULL if events disabled.
 *
 * @return 0 if KO, !=0 if OK
 */
int rawx_event_init(server_rec *s, const char *addr);


/**
 * Destroy event mechanism
 */
void rawx_event_destroy(void);

/**
 * Send event to event agent. This function adds "when" token automatically.
 *
 * @event_type name of the event
 * @data_json data event in json (this function will free it)
 *
 * @return 0 if KO, !=0 if OK
 */
int rawx_event_send(const char *event_type, GString *data_json);

#endif /*OIO_SDS__rawx_apache2__src__rawx_event_h*/
