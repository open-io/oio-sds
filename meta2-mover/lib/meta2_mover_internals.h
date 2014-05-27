#ifndef GS_META2_MOVER__H
# define GS_META2_MOVER__H 1
# ifndef G_LOG_DOMAIN
#  define G_LOG_DOMAIN "grid.meta2.mover"
# endif
# include <stdlib.h>
# include <string.h>
# include <errno.h>
# include <metautils/lib/metautils.h>
# include <metautils/lib/metacomm.h>
// TODO FIXME factorize these macroswith those present in metautils
# define GS_ERROR_NEW(CODE,FMT,...) NEWERROR(CODE, FMT, ##__VA_ARGS__)
# define GS_ERROR_STACK(E) g_prefix_error((E), "from(%s:%d,%s) ", __FILE__, __LINE__, __FUNCTION__)

struct xcid_s {
	container_id_t cid;
	gchar str[STRLEN_CONTAINERID];
	struct gs_container_location_s *location;
};

struct xaddr_s {
	addr_info_t addr;
	gchar str[STRLEN_ADDRINFO];
	struct metacnx_ctx_s cnx;
};

/* Utils features --------------------------------------------------------- */

GError* xaddr_init_from_addr(struct xaddr_s *x, const addr_info_t *ai);

GError* xaddr_init_from_url(struct xaddr_s *x, const gchar *url);

struct xcid_s * xcid_from_hexa(const gchar *h);

void xcid_free(struct xcid_s *x);

/* Load-Balancing features ------------------------------------------------- */

extern time_t interval_update_services;

const service_info_t* get_available_meta2_from_conscience(const gchar * ns_name, const addr_info_t *avoid);

void meta2_mover_clean_services(void);

gboolean meta2_mover_srv_is_source(addr_info_t *ai);

const gchar* meta2_mover_get_ns(void);

#endif /* GS_META2_MOVER__H */
