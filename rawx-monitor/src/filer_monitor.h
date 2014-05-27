#ifndef FILER_MONITOR_H
# define FILER_MONITOR_H
# ifndef G_LOG_DOMAIN
#  define G_LOG_DOMAIN "vol.monitor"
# endif
# include <metautils/lib/metautils.h>
# include <net-snmp/net-snmp-config.h>
# include <net-snmp/net-snmp-includes.h>
# define FILER_VOLTYPE_VOL 1
# define FILER_VOLTYPE_LUN 2
# ifdef HAVE_EXTRA_DEBUG
#  define XTRACE(FMT,...) TRACE("%s|"FMT,__FUNCTION__,##__VA_ARGS__)
# else
#  define XTRACE(...) 
# endif

struct snmp_auth_s {
	int version;
	char community[128];
	char security_name[128];
};

struct filer_auth_s {
	char user[256];
	char passwd[256];
};

struct enterprise_s;

struct filer_s;

struct volume_statistics_s;

struct volume_s; /**< Hidden, enterprise-dependant */

struct filer_ctx_s; /**< Hidden, enterprise-dependant */

/* ------------------------------------------------------------------------- */

typedef gboolean (*api_init_f) (struct enterprise_s *e, GError **err);

typedef gboolean (*api_close_f) (struct enterprise_s *e, GError **err);

/*filer lifecycle*/

typedef struct filer_ctx_s* (*filer_ctx_initiator_f) (struct filer_s *filer, GError **err);

typedef void (*filer_ctx_cleaner_f) (struct filer_ctx_s *ctx);

typedef gboolean (*filer_ctx_refresher_f) (struct filer_s *filer, GError **err);

/*filer actions*/

typedef struct volume_s** (*filer_vol_lister_f) (struct filer_s *filer, GError **err);

typedef struct volume_s* (*filer_vol_getter_f) (struct filer_s *filer, const char *name, GError **err);

typedef int (*filer_vol_monitor_f) (struct volume_s *vol, struct volume_statistics_s *st, GError **err);

/*Volume accessors*/

typedef oid (*volume_id_getter_f) (struct volume_s *vol);

typedef const char* (*volume_name_getter_f) (struct volume_s *vol);

typedef int (*volume_type_getter_f) (struct volume_s *vol);


struct filer_s {
	char str_addr[64];
	oid oid_enterprise;
	struct enterprise_s *enterprise;

	struct {
		struct snmp_auth_s snmp;
		struct filer_auth_s filer;
	} auth;

	struct filer_ctx_s *ctx;
};

struct enterprise_s {
	char name[32];
	oid code;

	gpointer udata;
	api_init_f init_api;
	api_close_f close_api;

	filer_ctx_initiator_f init_filer;
	filer_ctx_cleaner_f clean_filer;
	filer_ctx_refresher_f refresh_filer;

	filer_vol_lister_f get_volumes;
	filer_vol_getter_f get_named_volume;
	filer_vol_monitor_f monitor_volume;
	
	/* accessors to volume */
	volume_id_getter_f get_id;
	volume_name_getter_f get_name;
	volume_type_getter_f get_type;
};

struct volume_statistics_s {
	gint64 free_space;
	gint64 used_space;
	gint64 cpu_idle;/**<average cpu-idle*/
	gint64 net_idle;/**<network interfaces idle*/
	gint64 io_idle;/**<disks idle*/
	gint64 perf_idle;
};


/* SNMP common features ---------------------------------------------------- */

size_t oid_snprint(char *dst, size_t dst_size, oid *name, size_t name_len);

size_t snmp_get_error(char *dst, size_t dst_size, netsnmp_session *session);

netsnmp_session* snmp_init(netsnmp_session *base_session, gchar *host,
	struct snmp_auth_s *snmp_auth, GError **err);

struct string_mapping_s {
	int id;
	gchar name[256];
};

struct string_mapping_s** snmp_get_strings(netsnmp_session *session, oid *prefix, size_t prefix_size, GError **err);

struct int_mapping_s {
	int id;
	gint64 i64;
};

struct int_mapping_s** snmp_get_integers(netsnmp_session *session, oid *prefix, size_t prefix_size, GError **err);

gboolean snmp_get_int(netsnmp_session *s, oid *what, size_t what_len, gint64 *i64, GError **err);

gboolean snmp_get_template_int(netsnmp_session *s, oid *what, size_t what_len, oid which, gint64 *i64, GError **err);

/* RFC1213 */

gboolean snmp_get_enterprise_code(netsnmp_session *session, oid *code, GError **error);

gboolean snmp_get_interface_index(netsnmp_session *s, oid *itfIndex, GError **err);

gboolean snmp_get_interface_speed(netsnmp_session *s, oid itfIndex, gint64 *itfSpeed, GError **err);

/* Enterprises specifics */

void enterprises_init(void);

void enterprises_register(struct enterprise_s *e);

struct enterprise_s* enterprises_get_instance(oid needle);

struct filer_s* filer_init(const gchar *host, struct snmp_auth_s *snmp_auth,
	struct filer_auth_s *auth, GError **err);

void filer_fini(struct filer_s *filer);

#endif
