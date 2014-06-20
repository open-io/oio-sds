#ifndef HC_http_put_h
# define HC_http_put_h 1
# include <glib.h>
# include <metatypes.h>

struct http_put_s;

/**
 * Callback used to fill the request.
 *
 * This callback must copy at most s bytes in b.
 *
 * @param user_data user data
 * @param b where to store data
 * @param s size of the buffer b
 *
 * @return number of bytes written in b
 */
typedef ssize_t (*http_put_input_f) (void *user_data, char *b, size_t s);

/**
 * Create a new http put request.
 *
 * @cb_input callback to read data
 * @cb_input_data user data used by the callback cb_input
 * @data_length size of the complete data to send
 * @timeout_cnx timeout for connection phase in seconds
 * @timeout_op timeout for transfer operation in seconds
 *
 * @return handle on this http request or NULL in case of error
 */
struct http_put_s *http_put_create(http_put_input_f cb_input, gpointer cb_input_data, size_t data_length, long timeout_cnx, long timeout_op);

/**
 * Add a new destination where to send data.
 *
 * @param p http request handle
 * @url destination url
 * @user_data whatever the caller want but two dests must not have the same
 * user data pointer
 *
 * @note user_data is used as id to obtain information about the request so
 * all destinations must have different user_data.
 *
 * @return handle on this destination
 */
struct http_put_dest_s *http_put_add_dest(struct http_put_s *p, const gchar *url, gpointer user_data);

/**
 * Add a header for this destination.
 *
 * @param dest destination handle
 * @param key one key header
 * @val_fmt value of the key
 *
 */
void http_put_dest_add_header(struct http_put_dest_s *dest, const gchar *key, const gchar *val_fmt, ...) __attribute__ ((format (printf, 3, 4)));

/**
 * Start all put requests.
 *
 * In this function, the callback cb_input will be used to retrieve data to
 * send when it's necessary.
 *
 * For each response, cb_header will be used to trigger action on destination
 * user_data.
 *
 * In case of error with some destinations, a flag is set on them.
 *
 * This function can be called several times to retry failed requests.
 *
 * @param p http put handle
 *
 * @return error FIXME
 */
GError *http_put_run(struct http_put_s *p);

/**
 * Get the number of failed requests.
 *
 * @param p http put handle
 *
 * @return number of failure
 */
guint http_put_get_failure_number(struct http_put_s *p);

/**
 * Compute the md5 of the whole buffer so it must be called after run function.
 *
 * @param p http put handle
 * @param buffer will be filled with the hash
 * @param size buffer size (must be the same as md5 size)
 */
void http_put_get_md5(struct http_put_s *p, guint8 *buffer, gsize size);

/**
 * Get a pointer on data sent in this request.
 *
 * This function must be called only after the end of the request.
 *
 * @param p http put handle
 * @param[out] buffer return a pointer on data sent
 * @param[out] size return the size of data sent
 */
void http_put_get_buffer(struct http_put_s *p, const gchar **buffer, gsize *size);

/**
 * Get all user_data linked to successful destinations.
 *
 * @param p http put handle
 *
 * @return list of user_data (list must be freed by caller)
 */
GSList *http_put_get_success_dests(struct http_put_s *p);

/**
 * Get all user_data linked to failed destinations.
 *
 * @param p http put handle
 *
 * @return list of user_data (list must be freed by caller)
 */
GSList *http_put_get_failure_dests(struct http_put_s *p);

/**
 * Get response header for destination represented its user_data.
 *
 * @param p http put handle
 * @param user_data data pointer used to add a destination
 * @param header header key
 *
 * @return value corresponding to this header or NULL if user_data or
 * header not found
 *
 * @note the return value must not be freed by caller, it will be free
 * during http_put_destroy.
 */
const gchar *http_put_get_header(struct http_put_s *p, gpointer user_data, const gchar *header);

/**
 * Get http code for destination represented its user_data.
 *
 * @param p http put handle
 * @param user_data data pointer used to add a destination
 *
 * @return valid http code or 0 if request failed (connection failed...)
 */
guint http_put_get_http_code(struct http_put_s *p, gpointer user_data);

/**
 * Free all destinations.
 * It is useful to add spare destination to retry transfer.
 *
 * @param p http put handle
 */
void http_put_clear_dests(struct http_put_s *p);

/**
 * Free http_put and all destinations
 *
 * @param p http_put to free
 */
void http_put_destroy(struct http_put_s *p);

#endif // HC_http_put_h
