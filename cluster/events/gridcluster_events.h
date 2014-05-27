#ifndef __GRIDCLUSTER_EVENTS_H__
# define __GRIDCLUSTER_EVENTS_H__

# include <metautils/lib/metautils.h>

/**
 * Mandatory field
 */
#ifndef GRIDCLUSTER_EVTFIELD_AGGRNAME
# define GRIDCLUSTER_EVTFIELD_AGGRNAME   "AGGRNAME"
#endif

#ifndef  GRIDCLUSTER_EVTFIELD_CID
# define GRIDCLUSTER_EVTFIELD_CID   "CID"
#endif

#ifndef  GRIDCLUSTER_EVTFIELD_UEID
# define GRIDCLUSTER_EVTFIELD_UEID  "UEID"
#endif

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



/****************************************************************************/


#define GRIDCLUSTER_EVENT_XATTR_CID   "user.grid.agent.incoming-container"
#define GRIDCLUSTER_EVENT_XATTR_SEQ   "user.grid.agent.incoming-sequence"
#define GRIDCLUSTER_EVENT_XATTR_TIME  "user.grid.agent.incoming-time"


/**
 *
 * @param event
 * @param dirbase
 * @param seq
 */
GError* gridcluster_event_SaveNewEvent(struct event_config_s *evt_config, gridcluster_event_t *evt);

/**
 * @param event
 * @param key
 * return value
 */
gchar* gridcluster_event_get_string(gridcluster_event_t *event, const gchar *key);


int gridcluster_eventxattr_get_incoming_time(const gchar *path, time_t *t);
int gridcluster_eventxattr_get_seq(const gchar *path, gint64 *i64);
int gridcluster_eventxattr_get_container_id(const gchar *path, container_id_t *id, gchar *str, gsize str_len);



#endif /*__GRIDCLUSTER_EVENTHANDLER_H__*/
