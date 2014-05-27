#ifndef _META2_TEST_COMMON_H
#define _META2_TEST_COMMON_H 1

struct meta2_backend_s;
struct hc_url_s;

/**
 * Function taking a `struct meta2_backend_s *` as parameter
 * and returning nothing.
 */
typedef void (*repo_test_f) (struct meta2_backend_s *m2);

/**
 * Function taking a `struct meta2_backend_s *` and
 * a `struct hc_url_s *` as parameters and returning nothing.
 */
typedef void (*container_test_f) (struct meta2_backend_s *m2,
		struct hc_url_s *url);

void debug_beans_list(GSList *l);
void debug_beans_array(GPtrArray *v);

GSList* create_alias(struct meta2_backend_s *m2b, struct hc_url_s *url,
		const gchar *polname);

/**
 * Run a function on a simulated backend.
 */
void repo_wrapper(const gchar *ns, repo_test_f fr);

/**
 * Run a function on a simulated backend with one container.
 */
void container_wrapper(container_test_f cf);
#endif

