#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "rawx-monitor.snmp"
#endif

#include <metautils/lib/metautils.h>

#include "filer_monitor.h"

static struct enterprise_s **enterprises = NULL;

void
enterprises_init(void)
{
	enterprises = g_malloc0(sizeof(struct enterprise_s*));
}

void
enterprises_register(struct enterprise_s *e)
{
	guint len;
	
	XTRACE("Entering");
	len = g_strv_length((gchar**) enterprises);
	enterprises = g_realloc(enterprises, (len+2) * sizeof(struct enterprise_s*));
	enterprises[len] = e;
	enterprises[len+1] = NULL;
	XTRACE("Added at %d", len);
}

struct enterprise_s*
enterprises_get_instance(oid needle)
{
	struct enterprise_s **ptr;
	XTRACE("Entering");
	for (ptr=enterprises; *ptr ;ptr++) {
		if (needle == (*ptr)->code) {
			XTRACE("Found %p", *ptr);
			return *ptr;
		}
	}
	XTRACE("Not found");
	return NULL;
}

struct filer_s*
filer_init(const gchar *host, struct snmp_auth_s *snmp_auth,
	struct filer_auth_s *auth, GError **err)
{
	struct filer_s *filer;
	char wrk_host[sizeof(filer->str_addr)];
	oid oid_enterprise;
	struct enterprise_s *enterprise = NULL;

	/* Sanity checks */
	if (!host) {
		GSETERROR(err, "Invalid filer address");
		return NULL;
	}
	if (!snmp_auth) {
		GSETERROR(err, "Invalid snmp authentication info");
		return NULL;
	}
	if (!auth) {
		GSETERROR(err, "Invalid filer authentication info");
		return NULL;
	}

	bzero(wrk_host, sizeof(wrk_host));
	g_strlcpy(wrk_host, host, sizeof(host));
	
	do {
		netsnmp_session *session = NULL;
		netsnmp_session snmp_session;
		gboolean rc;

		bzero(&snmp_session, sizeof(snmp_session));
		if (!(session = snmp_init(&snmp_session, wrk_host, snmp_auth, err))) {
			GSETERROR(err, "Failed to init the SNMP session");
			return NULL;
		}
		rc = snmp_get_enterprise_code(session, &oid_enterprise, err);
		snmp_close(session);
		if (!rc) {
			GSETERROR(err, "Failed to determine the Enterprise ID for addr=[%s]", host);
			return NULL;
		}
	} while (0);

	/* Enterprise code managed, initiate a filer context */
	DEBUG("Enterprise addr=%s code=%lu", host, oid_enterprise);
	if (!(enterprise = enterprises_get_instance(oid_enterprise))) {
		GSETERROR(err, "Enterprise not managed");
		return NULL;
	}
	
	filer = g_malloc0(sizeof(*filer));
	g_strlcpy(filer->str_addr, host, sizeof(filer->str_addr));
	filer->oid_enterprise = oid_enterprise;
	filer->enterprise = enterprise;
	memcpy(&(filer->auth.snmp), snmp_auth, sizeof(filer->auth.snmp));
	memcpy(&(filer->auth.filer), auth, sizeof(filer->auth.filer));

	if (!(filer->ctx = enterprise->init_filer(filer, err))) {
		GSETERROR(err, "Failed to load the filer context");
		g_free(filer);
		return NULL;
	}

	return filer;
}

void
filer_fini(struct filer_s *filer)
{
	struct enterprise_s *e;

	if (!filer) {
		WARN("Invalid parameter");
		return;
	}

	e = filer->enterprise;
	if (e) {
		if (filer->ctx) 
			e->clean_filer(filer->ctx);
		filer->enterprise = NULL;
	}

	bzero(filer, sizeof(*filer));
	g_free(filer);
}

