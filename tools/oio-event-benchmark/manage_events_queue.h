#ifndef OIO_SDS__tools__benchmark_event__manage_events_queue_h
# define OIO_SDS__tools__benchmark_event__manage_events_queue_h

/**
 * Initialize event mechanism
 *
 * @addr event agent address or NULL if events disabled.
 *
 * @return 0 if KO, !=0 if OK
 */
GError* manage_events_queue_init(const char *addr);


/**
 * Destroy event mechanism
 */
void manage_events_queue_destroy(void);

/**
 * Send event to event agent. This function adds "when" token automatically.
 *
 * @event_type name of the event
 * @data_json data event in json (this function will free it)
 *
 * @return NULL if OK, or a GError describing the problem
 */
GError* manage_events_queue_send(const char *event_type, struct oio_url_s *url,
		GString *data_json);

#endif /*OIO_SDS__tools__benchmark_event__manage_events_queue_h*/
