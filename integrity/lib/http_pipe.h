#ifndef HC_http_pipe_h
# define HC_http_pipe_h 1
# include <glib.h>

struct http_pipe_s;

struct http_pipe_s * http_pipe_create(const gchar *from, const gchar *to);

void http_pipe_force_header(struct http_pipe_s *p, const gchar *name,
		const gchar *value);

typedef gboolean (*http_pipe_header_filter_cb) (gpointer u, const gchar *h);

void http_pipe_filter_headers(struct http_pipe_s *p,
		http_pipe_header_filter_cb filter, gpointer u);

typedef void (*http_pipe_data_filter_cb) (gpointer u, guint8 *b, gsize blen);

void http_pipe_filter_data(struct http_pipe_s *p,
		http_pipe_data_filter_cb filter, gpointer u);

GError *http_pipe_run(struct http_pipe_s *p);

void http_pipe_destroy(struct http_pipe_s *p);

#endif // HC_http_pipe_h
