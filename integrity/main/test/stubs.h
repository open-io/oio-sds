#include "../lib/alert.h"
#include <rawx_client.h>

gboolean alert(const gchar* domain, int criticity, const gchar* message);

gboolean rawx_client_get_directory_data(rawx_session_t * session, hash_sha256_t chunk_id, struct content_textinfo_s *content, struct chunk_textinfo_s *chunk, GError ** error);
