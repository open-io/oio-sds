#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.metautils"
#endif

#include "metautils.h"

int
main(int argc, char **args)
{
	gchar str[256], hexa[1024];
	struct addr_info_s addr;
	int i;

	for (i=1; i<argc ; i++) {
		memset(&addr, 0, sizeof(addr));
		if (grid_string_to_addrinfo(args[i], NULL, &addr)) {
			memset(str, 0, sizeof(str));
			addr_info_to_string(&addr, str, sizeof(str));
			memset(hexa, 0, sizeof(hexa));
			buffer2str(&addr, sizeof(addr), hexa, sizeof(hexa));
			g_print("%s %s\n", str, hexa);
		}
	}

	return 0;
}

