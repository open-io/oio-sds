#include <stdio.h>
#include <stdlib.h>

#include <sqlite3.h>

#include <metautils/lib/metautils.h>

#include <meta2v2/meta2_backend.h>
#include <meta2v2/meta2_dedup_utils.h>
#include <meta2v2/meta2_test_common.h>

struct meta2_backend_s;
struct hc_url_s;

static void
test_content_dedup(gconstpointer test_data)
{
	guint num_duplicates = *(guint*)test_data;

	void change_chunk_hash(GSList *beans, guint start) {
		guint8 counter = start;
		for (GSList *cursor = beans;
				cursor;
				cursor = cursor->next) {
			if (DESCR(cursor->data) == &descr_struct_CHUNKS) {
				GByteArray *hash = CHUNKS_get_hash(cursor->data);
				hash->data[0] = counter;
				CHUNKS_set_hash(cursor->data, hash); // no-op because same pointer
				counter++;
			} else if (DESCR(cursor->data) == &descr_struct_CONTENTS_HEADERS) {
				GByteArray *hash = g_byte_array_sized_new(16);
				GRID_INFO("---- forging content hash ----");
				for (guint8 i = 0; i < 16; i++) {
					hash->data[i] = i + 1;
				}
				CONTENTS_HEADERS_set_hash(cursor->data, hash);
			}
		}
	}

	void test(struct meta2_backend_s *m2, struct hc_url_s *url) {
		GError *err;
		/* Generate a list of beans */
		GSList *beans = create_alias(m2, url, NULL);
		/* Change the hash of the chunk beans (0 by default) */
		change_chunk_hash(beans, 0);
		/* Put the beans in the database */
		err = meta2_backend_put_alias(m2, url, beans, NULL, NULL);
		g_assert_no_error(err);
		_bean_cleanl2(beans);

		/* Generate other contents with same hashes */
		for (guint counter = 1; counter <= num_duplicates; counter++) {
			/* Suffix the base url */
			gchar *url_str = g_strdup_printf("%s_%d", hc_url_get(url, HCURL_WHOLE),
					counter);
			struct hc_url_s *url2 = hc_url_init(url_str);
			g_free(url_str);
			GSList *beans2 = create_alias(m2, url2, NULL);
			change_chunk_hash(beans2, counter);
			err = meta2_backend_put_alias(m2, url2, beans2, NULL, NULL);
			g_assert_no_error(err);
			_bean_cleanl2(beans2);
		}

		err = meta2_backend_deduplicate_chunks(m2, url);
		g_assert_no_error(err);
	}
	container_wrapper(test);
}

int main(int argc, char **argv)
{
	if (!g_thread_supported())
		g_thread_init(NULL);
	g_set_prgname(argv[0]);

	g_test_init(&argc, &argv, NULL);
	g_log_set_default_handler(logger_stderr, NULL);
	logger_init_level(GRID_LOGLVL_TRACE);

	guint num_duplicates = 2;
	g_test_add_data_func("/meta2v2/backend/content/dedup",
			&num_duplicates, test_content_dedup);

	return g_test_run();
}


