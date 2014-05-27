#include "../lib/alert.h"
#include <rawx_client.h>
typedef gboolean  (*test_dept_alert_fun)(const gchar* , int , const gchar* );
void test_dept_alert_set(test_dept_alert_fun f);
gboolean  test_dept_proxy_alert(const gchar* domain, int criticity, const gchar* message);
typedef gboolean  (*test_dept_rawx_client_get_directory_data_fun)(rawx_session_t * , hash_sha256_t , struct content_textinfo_s *, struct chunk_textinfo_s *, GError ** );
void test_dept_rawx_client_get_directory_data_set(test_dept_rawx_client_get_directory_data_fun f);
gboolean  test_dept_proxy_rawx_client_get_directory_data(rawx_session_t * session, hash_sha256_t chunk_id, struct content_textinfo_s *content, struct chunk_textinfo_s *chunk, GError ** error);
