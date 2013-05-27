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

#ifndef __GRIDCLUSTER_EVENTS_H__
# define __GRIDCLUSTER_EVENTS_H__

# include <glib.h>
# include <metatypes.h>

typedef GHashTable gridcluster_event_t;

/**
 * @return
 */
gridcluster_event_t* gridcluster_create_event(void);

/**
 * @param event
 * @param err
 * @return 
 */
GByteArray* gridcluster_encode_event( gridcluster_event_t *event, GError **err );

/**
 * @param encoded
 * @param err
 * @return 
 */
gridcluster_event_t* gridcluster_decode_event( GByteArray *encoded, GError **err );

/**
 * @param encoded
 * @param encoded_size
 * @param err
 * @return 
 */
gridcluster_event_t* gridcluster_decode_event2( const guint8 * const encoded, gsize encoded_size, GError **err );

/**
 * @param event
 */
void gridcluster_destroy_event(gridcluster_event_t* event);


/**
 * @param pevent
 * @param ignored
 */
void gridcluster_event_gclean(gpointer pevent, gpointer ignored);


/**
 * @param event
 * @param key
 * @param value
 * @param value_size
 */
void gridcluster_event_add_string(gridcluster_event_t *event, const gchar *key, const gchar *value);

/**
 *
 * @param event
 * @param key
 * @param value
 * @param value_size
 */
void gridcluster_event_add_buffer(gridcluster_event_t *event, const gchar *key, const guint8 *value, gsize value_size);

/**
 * @param event
 * @param dst_type
 * @param dst_size
 * @return
 */
gsize gridcluster_event_get_type(gridcluster_event_t *event, gchar *dst_type, gsize dst_size);

/**
 *
 * @param event
 * @param str_type
 */
void gridcluster_event_set_type(gridcluster_event_t *event, const gchar *str_type);

#endif /*__GRIDCLUSTER_EVENTHANDLER_H__*/
