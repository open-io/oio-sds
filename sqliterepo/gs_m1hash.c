#include <metautils/lib/metautils.h>
#include "hash.h"

int
main(int argc, char **argv)
{
	if (argc < 2 || 1 != (argc % 2)) {
		g_printerr("Usage: %s (NAME TYPE)...\n", argv[0]);
		return 0;
	}

	for (int i=1; i<argc-1 ;i+=2) {
		const gchar *n = argv[i], *t = argv[i+1];
		struct hashstr_s *h = sqliterepo_hash_name(n, t);
		g_print("%s.%s %s.%s\n", n, t, hashstr_str(h), t);
		g_free(h);
	}
	return 0;
}

