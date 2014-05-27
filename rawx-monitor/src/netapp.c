#include <math.h>
#include <netapp_api.h>

#include "filer_monitor.h"
#include "netapp.h"

#define NETAPP_PREFIX 1,3,6,1,4,1,789

#define NETAPP_VOLTYPE_NFS 2
#define NETAPP_VOLTYPE_AGG 3

#define NM_PENDING_FREESPACE 0x01
#define NM_PENDING_MAXSPACE  0x02
#define NM_PENDING_ALL       0x03

#define LOG_RETURN(V,FMT,...) do { XTRACE(FMT,##__VA_ARGS__); return (V); } while (0)

#define AGGR_NAME_LEN 32
#define VOLUME_NAME_LEN 256

struct volume_s {
	struct enterprise_s *enterprise;
	struct filer_s *filer;
	char path[VOLUME_NAME_LEN];

	enum { VT_VOL , VT_LUN } type;
	union {
		struct {
			oid vol_id;
			oid lun_id;
		} lun;
		struct {
			oid vol_id;
		} vol;
	} id;

	gchar name[VOLUME_NAME_LEN];
};

struct filer_ctx_s {
	netsnmp_session snmp_session;
	netsnmp_session *session;
	na_server_t *na_session;
	struct {
		time_t last_update;
		
		struct volume_s **volumes;
		GList *aggregates;
		GHashTable *vol2aggr;
		GHashTable *disk2aggr;

		oid net_itf_index;
		gint64 net_in_max;
		gint64 net_out_max;
	} fixed;
	struct {
		time_t last_update;
		GHashTable *aggr2idle;/* (gchar*) -> (struct aggr2idle_s*) */
		gint64 cpu_idle;
		gint64 net_idle;
		/*accumulators*/
		gint64 net_out_last;
		gint64 net_in_last;
	} variable;
};

static oid oid_ifNetIn[] = {1,3,6,1,2,1,2,2,1,10};
static size_t oid_ifNetIn_size = sizeof(oid_ifNetIn)/sizeof(oid);

static oid oid_ifNetOut[] = {1,3,6,1,2,1,2,2,1,11};
static size_t oid_ifNetOut_size = sizeof(oid_ifNetOut)/sizeof(oid);

static oid oid_fsNames[] = {NETAPP_PREFIX, 1,5,4,1,2};
static size_t oid_fsNames_size = sizeof(oid_fsNames)/sizeof(oid);

static oid oid_fsTypes[] = {NETAPP_PREFIX, 1,5,4,1,23};
static size_t oid_fsTypes_size = sizeof(oid_fsTypes)/sizeof(oid);

static oid oid_fsUsedSpace[] = {NETAPP_PREFIX, 1,5,4,1,4};
static size_t oid_fsUsedSpace_size = sizeof(oid_fsUsedSpace)/sizeof(oid);

static oid oid_fsFreeSpace[] = {NETAPP_PREFIX, 1,5,4,1,5};
static size_t oid_fsFreeSpace_size = sizeof(oid_fsFreeSpace)/sizeof(oid);

static oid oid_lunNames[] = {NETAPP_PREFIX, 1,17,15,2,1,2};
static size_t oid_lunNames_size = sizeof(oid_lunNames)/sizeof(oid);

static oid oid_cpuIdle[] = {NETAPP_PREFIX, 1,2,1,5};
static size_t oid_cpuIdle_size = sizeof(oid_cpuIdle)/sizeof(oid);

/*volume accessors*/
static oid netapp_get_volume_id(struct volume_s *vol);
static const char* netapp_get_volume_name(struct volume_s *vol);
static int netapp_get_volume_type(struct volume_s *vol);

/*filer actions*/
static struct volume_s** netapp_load_volumes(struct filer_s *filer, GError **error);
static struct volume_s** netapp_get_filer_luns(netsnmp_session *session, GError **error);
static struct volume_s** netapp_get_filer_volumes(netsnmp_session *session, GError **error);
static struct volume_s** netapp_get_volumes(struct filer_s *filer, GError **error);
static struct volume_s* netapp_get_volume(struct filer_s *filer, const char *name, GError **error);
static gboolean netapp_monitor_volume(struct volume_s *vol, struct volume_statistics_s *st, GError **err);

/**/
static gboolean netapp_api_close(struct enterprise_s *e, GError **err);
static gboolean netapp_api_init(struct enterprise_s *e, GError **err);

/* Retrieve a list of Aggregate-to-Volume list
 * covering all the aggregates of the given filer */
static GHashTable*
zapi_get_vol2aggr(na_server_t *s, GError **err)
{
	GHashTable *ht;
	na_elem_t *out, *in;
	na_elem_t *vol_info_array, *vol_info, *aggr_info_array, *aggr_info;
	na_elem_iter_t iter_aggr, iter_vol;

	XTRACE("Entering");
	
	/* the target aggregate is optional, and that is fine, we will
	 * get the information about all the agregates */
	in = na_elem_new("aggr-list-info");
	out = na_server_invoke_elem(s, in);
	na_elem_free(in);

	/* Error management */
	if (!out) {
		GSETERROR(err, "ZAPI error : no output");
		LOG_RETURN(NULL,"Failure (zapi error)");
	}
	if (na_results_status(out) != NA_OK) {
		na_elem_free(out);
		GSETERROR(err, "NetApp filer error : (%d) %s", na_results_errno(out), na_results_reason(out));
		LOG_RETURN(NULL,"Failure (server)");
	}

	/* Reply's content handling */
	ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	aggr_info_array = na_elem_child(out, "aggregates");
	for (iter_aggr=na_child_iterator(aggr_info_array); (aggr_info=na_iterator_next(&iter_aggr)) ;) {
		vol_info_array = na_elem_child(aggr_info,"volumes");
		for (iter_vol=na_child_iterator(vol_info_array); (vol_info=na_iterator_next(&iter_vol)) ;) {
			const char *vname, *aname;

			vname = na_child_get_string(vol_info,"name");
			aname = na_child_get_string(aggr_info,"name");
			g_hash_table_insert(ht, g_strdup(vname), g_strdup(aname));
			XTRACE("Saved : vol[%s] -> agr[%s]", vname, aname);
		}
	}
	
	na_elem_free(out);
	LOG_RETURN(ht,"Success");
}

static GHashTable*
zapi_get_disk2aggr(na_server_t *s, GError **err)
{
	GHashTable *ht;
	na_elem_t *out, *in;
	na_elem_t *disk_info_array, *disk_info;
	na_elem_iter_t iter_disk;

	XTRACE("Entering");

	/* the target aggregate is optional, and that is fine, we will
	 * get the information about all the agregates */
	in = na_elem_new("disk-list-info");
	out = na_server_invoke_elem(s, in);

	/* Error management */
	if (!out) {
		na_elem_free(in);
		GSETERROR(err, "ZAPI error : no output");
		LOG_RETURN(NULL,"Failure (zapi error)");
	}
	if (na_results_status(out) != NA_OK) {
		na_elem_free(in);
		na_elem_free(out);
		GSETERROR(err, "NetApp filer error : (%d) %s", na_results_errno(out), na_results_reason(out));
		LOG_RETURN(NULL,"Failure (server)");
	}

	/* Reply's content handling */
	ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	disk_info_array = na_elem_child(out,"disk-details");
	for (iter_disk=na_child_iterator(disk_info_array); (disk_info=na_iterator_next(&iter_disk)) ;) {
		const char *aname, *dname;

		/* normal case for flex-vol */
		aname = na_child_get_string(disk_info,"aggregate");
		
		if (!aname) /* special case for trad-vol volumes */
			aname = na_child_get_string(disk_info,"volume");
			
		if (aname) {
			dname = na_child_get_string(disk_info,"disk-uid");
		 	g_hash_table_insert(ht, g_strdup(dname), g_strdup(aname));
			XTRACE("Saved : disk[%s] -> aggr[%s]", dname, aname);
		}
	}
	
	na_elem_free(in);
	na_elem_free(out);
	LOG_RETURN(ht,"Success");
}

static GHashTable*
zapi_get_disk2idle(na_server_t *s, GError **err)
{
	GHashTable *ht;
	na_elem_t *out, *in;
	na_elem_t *instances, *instance;
	na_elem_iter_t iter_c, iter_i;

	XTRACE("Entering");

	in = na_elem_new("perf-object-get-instances");
	na_child_add_string(in, "objectname", "disk");

	do {
		na_elem_t *counters = na_elem_new("counters");
		na_child_add_string(counters, "counter", "disk_busy");
		na_child_add_string(counters, "counter", "base_for_disk_busy");
		na_child_add(in, counters);
	} while (0);

	out = na_server_invoke_elem(s, in);
	na_elem_free(in);
	
	/* Error management */
	if (!out) {
		GSETERROR(err, "ZAPI error : no output");
		LOG_RETURN(NULL,"Failure (zapi error)");
	}
	if (na_results_status(out) != NA_OK) {
		na_elem_free(out);
		GSETERROR(err, "NetApp filer error : (%d) %s", na_results_errno(out), na_results_reason(out));
		LOG_RETURN(NULL,"Failure (server)");
	}

	/* Reply's content handling */
	ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	instances = na_elem_child(out, "instances");
	for (iter_i=na_child_iterator(instances); (instance = na_iterator_next(&iter_i)); ) {
		const char *iname;
		na_elem_t *counters, *counter;
		gint64 busy=1, busy_base=0;
		gint idle;

		iname = na_child_get_string(instance, "name");
		counters = na_elem_child(instance, "counters");

		for (iter_c=na_child_iterator(counters); (counter = na_iterator_next(&iter_c)) ; ) {
			const char *cname;
			gint i;

			cname = na_child_get_string(counter, "name");
			i = na_child_get_int(counter, "value", 0);
			if (cname && *cname=='b' && 0==g_ascii_strcasecmp(cname,"base_for_disk_busy"))
				busy_base = i>0 ? i : 1;
			if (cname && *cname=='d' && 0==g_ascii_strcasecmp(cname,"disk_busy"))
				busy = i>0 ? i : 1;
		}

		busy_base /= busy;
		idle = 100LL - busy_base;
		g_hash_table_insert(ht, g_strdup(iname), GINT_TO_POINTER(idle));
		XTRACE("Saved : disk[%s] -> idle[%d]", iname, idle);
	}
	
	na_elem_free(out);
	LOG_RETURN(ht,"Success");
}

static GList*
zapi_list_aggregates(na_server_t *s, GError **err)
{
	GList *la;
	na_elem_t *out, *in;
	na_elem_t *aggr_info_array, *aggr_info;
	na_elem_iter_t iter_aggr;

	XTRACE("Entering");

	in = na_elem_new("aggr-list-info");
	out = na_server_invoke_elem(s, in);
	na_elem_free(in);

	if (!out) {
		GSETERROR(err, "ZAPI error : no output");
		LOG_RETURN(NULL,"Failure (zapi error)");
	}
	if (na_results_status(out) != NA_OK) {
		na_elem_free(out);
		GSETERROR(err, "NetApp filer error : (%d) %s", na_results_errno(out), na_results_reason(out));
		LOG_RETURN(NULL,"Failure (server)");
	}

	la = NULL;
	aggr_info_array = na_elem_child(out, "aggregates");
	for (iter_aggr=na_child_iterator(aggr_info_array); (aggr_info=na_iterator_next(&iter_aggr)) ;) {
		const char *aname;
		aname = na_child_get_string(aggr_info,"name");
		la = g_list_append(la, g_strdup(aname));
	}
	
	na_elem_free(out);
	LOG_RETURN(la,"Success");
}

/*Volume accessors*/
static const char*
netapp_get_volume_aggregate(struct volume_s *vol)
{
	return g_hash_table_lookup(vol->filer->ctx->fixed.vol2aggr, vol->name);
}

static void
netapp_free_volume_array(struct volume_s **volumes)
{
	if (volumes)
		g_strfreev((gchar**)volumes);
}

static void
netapp_clean_filer(struct filer_ctx_s *ctx)
{
	if (ctx->fixed.volumes)
		netapp_free_volume_array(ctx->fixed.volumes);
	memset(ctx, 0x00, sizeof(*ctx));
	g_free(ctx);
}

oid
netapp_get_volume_id(struct volume_s *vol)
{
	switch (vol->type) {
	case VT_VOL:
		return vol->id.vol.vol_id;
	case VT_LUN:
		return vol->id.lun.lun_id;
	default:
		return 0;
	}
}

const char*
netapp_get_volume_name(struct volume_s *vol)
{
	return vol->path;
}

int
netapp_get_volume_type(struct volume_s *vol)
{
	return vol->type;
}

/*Filer actions*/

struct volume_s **
netapp_get_filer_luns(netsnmp_session *session, GError **error)
{
	guint i;
	GPtrArray *gpa;
	struct volume_s **result = NULL;
	struct string_mapping_s **names;
	size_t names_len;

	XTRACE("Entering");
	names = snmp_get_strings(session, oid_lunNames, oid_lunNames_size, error);
	if (!names) {
		GSETERROR(error, "No LUNs available");
		LOG_RETURN(NULL,"Failure (no names)");
	}

	names_len = g_strv_length((gchar**)names);

	gpa = g_ptr_array_new();
	for (i=0; i<names_len ;i++) {
		struct volume_s *vol;

		vol = g_try_malloc0(sizeof(struct volume_s));
		vol->type = VT_LUN;
		vol->id.lun.lun_id = i;
		g_strlcpy(vol->path, names[i]->name, sizeof(vol->path));

		g_ptr_array_add(gpa, vol);
	}
	
	g_ptr_array_add(gpa, NULL);
	result = (struct volume_s**) g_ptr_array_free(gpa, FALSE);

	g_strfreev((gchar**)names);
	LOG_RETURN(result,"Found %u LUNs", g_strv_length((gchar**)result));
}

struct volume_s **
netapp_get_filer_volumes(netsnmp_session *session, GError **error)
{
	guint i;
	GPtrArray *gpa;
	struct volume_s **result = NULL;
	struct int_mapping_s **types;
	struct string_mapping_s **names;
	size_t types_len, names_len;

	XTRACE("Entering");
	names = snmp_get_strings(session, oid_fsNames, oid_fsNames_size, error);
	types = snmp_get_integers(session, oid_fsTypes, oid_fsTypes_size, error);
	names_len = names ? g_strv_length((gchar**)names) : 0;
	types_len = types ? g_strv_length((gchar**)types) : 0;

	if (types_len != names_len) {
		GSETERROR(error, "netapp : no data match (#types=%u and #names=%u)", types_len, names_len);
		goto exit_label;
	}

	gpa = g_ptr_array_new();
	for (i=0; i<types_len ;i++) {
		if (types[i]->i64 == NETAPP_VOLTYPE_NFS) {
			struct volume_s *vol;

			XTRACE("Reguler volume matched (type=%"G_GINT64_FORMAT")", types[i]->i64);
			vol = g_try_malloc0(sizeof(struct volume_s));
			vol->type = VT_VOL;
			vol->id.vol.vol_id = i;
			g_strlcpy(vol->path, names[i]->name, sizeof(vol->path));

			g_ptr_array_add(gpa, vol);
		}
		else
			XTRACE("Unexpected Volume type (type=%"G_GINT64_FORMAT")", types[i]->i64);
	}

	g_ptr_array_add(gpa, NULL);
	result = (struct volume_s**) g_ptr_array_free(gpa, FALSE);

exit_label:
	g_strfreev((gchar**)names);
	g_strfreev((gchar**)types);
	LOG_RETURN(result,"Found %u volumes", g_strv_length((gchar**)result));
}

struct volume_s**
netapp_load_volumes(struct filer_s *filer, GError **error)
{
	struct volume_s *vol, **volumes, **luns, **all;
	size_t volumes_size, luns_size;

	XTRACE("Entering");

	/* Collect both volumes and LUNs */
	volumes = netapp_get_filer_volumes(filer->ctx->session, error);
	volumes_size = g_strv_length((gchar**)volumes);
	
	luns = netapp_get_filer_luns(filer->ctx->session, error);
	luns_size = g_strv_length((gchar**)luns);

	XTRACE("Found %d volumes and %d LUNs", volumes_size, luns_size);

	all = g_malloc0(sizeof(struct volume_s*) * (volumes_size+luns_size+1));
	if (volumes) {
		if(volumes_size)
			memcpy(all, volumes, volumes_size * sizeof(struct volume_s*));
		g_free(volumes);
	}
	if (luns) {
		if (luns_size)
			memcpy(all+volumes_size, luns, luns_size * sizeof(struct volume_s*));
		g_free(luns);
	}

	/* Init some fields */
	for (volumes=all; (vol=*volumes) ;volumes++) {
		register char *ptr, *str;

		/*remove trailing slashes and blanks*/
		str = vol->path;
		for (ptr=str+strlen(str)-1; ptr>str && (g_ascii_isspace(*ptr) || *ptr=='/') ; ptr--)
			*ptr = '\0';

		/*remove leading multiple slashes*/
		if (*str == '/') {
			for (ptr=str+1; *ptr=='/' ;ptr++);
			str = ptr - 1;
		}
	
		/*build the volume's name from the volume's path*/
		if (g_str_has_prefix(str,"/vol/"))
			g_strlcpy(vol->name, str + sizeof("/vol/") - 1, sizeof(vol->name)-1);
		else
			g_strlcpy(vol->name, str, sizeof(vol->name)-1);

		vol->filer = filer;
		vol->enterprise = filer->enterprise;
	}

	LOG_RETURN(all,"Success");
}

static gboolean
netapp_refresh_volumes_list(struct filer_s *filer, GError **error)
{
	struct volume_s **new_volumes, **ptr_vol, **old_vol;

	XTRACE("Entering");

	if (!(new_volumes = netapp_load_volumes(filer, error))) {
		GSETERROR(error, "Failed to refresh the volume list");
		LOG_RETURN(FALSE,"Failure (volumes list loading)");
	}

	if (!filer->ctx->fixed.volumes) {
		filer->ctx->fixed.volumes = new_volumes;
		LOG_RETURN(TRUE,"Success (first loading)");
	}

	/* merge the old volumes on the old volumes in the new,
	 * this will copy the volume statistics, then keep only
	 * the latest volume list */
	for (ptr_vol=new_volumes; *ptr_vol ;ptr_vol++) {
		for (old_vol=filer->ctx->fixed.volumes; *old_vol ;old_vol++) {
			if (0 == g_ascii_strcasecmp((*ptr_vol)->path, (*old_vol)->path)) {
				memcpy(*ptr_vol, *old_vol, sizeof(struct volume_s));
				break;
			}
		}
	}
	
	netapp_free_volume_array(filer->ctx->fixed.volumes);
	filer->ctx->fixed.volumes = new_volumes;
	LOG_RETURN(TRUE,"Success (reload)");
}

static gboolean
netapp_refresh_network_definitions(struct filer_s *filer, GError **err)
{
	oid itfIndex;
	gint64 itfSpeed;
	
	XTRACE("Entering");
	
	if (!snmp_get_interface_index(filer->ctx->session, &itfIndex, err)) {
		GSETERROR(err, "Interface index not found");
		LOG_RETURN(FALSE,"Failure (interface index)");
	}
	if (!snmp_get_interface_speed(filer->ctx->session, itfIndex, &itfSpeed, err)) {
		GSETERROR(err, "Interface speed not found for index=%u", itfIndex);
		LOG_RETURN(FALSE,"Failure (interface bandwith)");
	}

	filer->ctx->fixed.net_itf_index = itfIndex;
	filer->ctx->fixed.net_in_max = filer->ctx->fixed.net_out_max = itfSpeed;
	LOG_RETURN(TRUE,"Success");
}

static struct filer_ctx_s*
netapp_init_filer(struct filer_s *filer, GError **err)
{
	struct filer_ctx_s *ctx;

	XTRACE("Entering");
	(void) filer;
	
	ctx = g_try_malloc0(sizeof(*ctx));
	if (!ctx) {
		GSETERROR(err,"Memory allocation failure");
		LOG_RETURN(NULL,"Failure (memory)");
	}

	/* Inits the SNMP session for this Filer */
	ctx->session = snmp_init(&(ctx->snmp_session), filer->str_addr, &(filer->auth.snmp), err);
	if (!ctx->session) {
		g_free(ctx);
		GSETERROR(err,"SNMP session error");
		LOG_RETURN(NULL,"Failure (snmp)");
	}

	/* Inits the Zapi session */
	ctx->na_session = na_server_open(filer->str_addr, 1, 0);
	if (!ctx->na_session) {
		snmp_close(ctx->session);
		g_free(ctx);
		GSETERROR(err,"OnTap Management API error : failed to start a session");
		LOG_RETURN(NULL,"Failure (na_session)");
	}
	na_server_style(ctx->na_session, NA_STYLE_LOGIN_PASSWORD);
	na_server_set_transport_type(ctx->na_session, NA_SERVER_TRANSPORT_HTTP, NULL);
	na_server_adminuser(ctx->na_session, filer->auth.filer.user, filer->auth.filer.passwd);
	
	return ctx;
}

static gboolean
netapp_refresh_fixed_filer_data(struct filer_s *filer, GError **err)
{
	register gboolean time_is_up;
	
	time_is_up = filer->ctx->fixed.last_update + 60L < time(0);

	if (time_is_up || !filer->ctx->fixed.volumes) {
		GHashTable *ht_vol2aggr, *ht_disk2aggr;
		GList *aggregates;
		
		if (!netapp_refresh_network_definitions(filer, err))
			LOG_RETURN(FALSE,"Failure (network)");
		if (!netapp_refresh_volumes_list(filer, err))
			LOG_RETURN(FALSE,"Failure (volumes)");
		
		aggregates = zapi_list_aggregates(filer->ctx->na_session, err);
		if (aggregates) {
			if (filer->ctx->fixed.aggregates) {
				g_list_foreach (filer->ctx->fixed.aggregates, (GFunc)g_free, NULL);
				g_list_free(filer->ctx->fixed.aggregates);
			}
			filer->ctx->fixed.aggregates = aggregates;
		}
			
		ht_vol2aggr = zapi_get_vol2aggr(filer->ctx->na_session, err);
		if (ht_vol2aggr) {
			if (filer->ctx->fixed.vol2aggr)
				g_hash_table_destroy(filer->ctx->fixed.vol2aggr);
			filer->ctx->fixed.vol2aggr = ht_vol2aggr;
			XTRACE("Mappings saved : vol2aggr (%u)", g_hash_table_size(filer->ctx->fixed.vol2aggr));
		}
		
		ht_disk2aggr = zapi_get_disk2aggr(filer->ctx->na_session, err);
		if (ht_disk2aggr) {
			if (filer->ctx->fixed.disk2aggr)
				g_hash_table_destroy(filer->ctx->fixed.disk2aggr);
			filer->ctx->fixed.disk2aggr = ht_disk2aggr;
			XTRACE("Mappings saved : disk2aggr (%u)", g_hash_table_size(filer->ctx->fixed.disk2aggr));
		}
	}

	filer->ctx->fixed.last_update = time(0);
	LOG_RETURN(TRUE, "Success (filer fixed data reloaded)");
}

static gboolean
netapp_refresh_filer_data(struct filer_s *filer, GError **err)
{
	gint64 in64, out64;
	gdouble in_idle, out_idle;
	GHashTable *ht_disk2idle;
	
	GList *l;
	GHashTableIter iter;
	GHashTable *ht_disk_counters;
	gpointer k, v;

	XTRACE("Entering");
	
	if (!netapp_refresh_fixed_filer_data(filer, err)) {
		GSETERROR(err, "Uncomplete or too old filer data");
		LOG_RETURN(FALSE, "Failure (uncomplete info)");
	}

	/* get CPU-idle */
	if (!snmp_get_template_int(filer->ctx->session, oid_cpuIdle, oid_cpuIdle_size,
			0, &(filer->ctx->variable.cpu_idle), err)) {
		GSETERROR(err, "Failed to get network output on interface %d", filer->ctx->fixed.net_itf_index);
		LOG_RETURN(FALSE, "Failure (oid_ifNetOut)");
	}
	XTRACE("cpuIdle = %"G_GINT64_FORMAT, filer->ctx->variable.cpu_idle);
	
	/* compute IO-idle */
	if (!snmp_get_template_int(filer->ctx->session, oid_ifNetIn, oid_ifNetIn_size,
			filer->ctx->fixed.net_itf_index, &in64, err)) {
		GSETERROR(err, "Failed to get network input on interface %d", filer->ctx->fixed.net_itf_index);
		LOG_RETURN(FALSE, "Failure (oid_ifNetIn)");
	}
	XTRACE("ifNetIn = %"G_GINT64_FORMAT, in64);
	
	if (!snmp_get_template_int(filer->ctx->session, oid_ifNetOut, oid_ifNetOut_size,
			filer->ctx->fixed.net_itf_index, &out64, err)) {
		GSETERROR(err, "Failed to get network output on interface %d", filer->ctx->fixed.net_itf_index);
		LOG_RETURN(FALSE, "Failure (oid_ifNetOut)");
	}
	XTRACE("ifNetOut = %"G_GINT64_FORMAT, out64);
	
	if (filer->ctx->variable.net_in_last > in64)
		in_idle = 99.0;
	else {
		in_idle = in64 - filer->ctx->variable.net_in_last;
		in_idle /= 1.0 * filer->ctx->fixed.net_in_max;
		in_idle = 100.0 * (1.0 - in_idle);
	}

	if (filer->ctx->variable.net_out_last > out64)
		out_idle = 99.0;
	else {
		out_idle = out64 - filer->ctx->variable.net_out_last;
		out_idle /= 1.0 * filer->ctx->fixed.net_out_max;
		out_idle = 100.0 * (1.0 - out_idle);
	}

	filer->ctx->variable.net_idle = floor(MIN(in_idle,out_idle));
	filer->ctx->variable.net_out_last = out64;
	filer->ctx->variable.net_in_last = in64;

	/* --------------------- */
	/* Collect the disk-idle */
	/* --------------------- */
	if (!filer->ctx->variable.aggr2idle)
		filer->ctx->variable.aggr2idle = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	ht_disk2idle = zapi_get_disk2idle(filer->ctx->na_session, err);
	if (!ht_disk2idle) {
		GSETERROR(err,"Failed to collect the filer's disk-idle");
		LOG_RETURN(FALSE,"Failure (Disk-idle)");
	}

	ht_disk_counters = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
	
	/* reset the counters and accumulators */
	for (l=filer->ctx->fixed.aggregates; l ; l=l->next) {
		g_hash_table_insert(ht_disk_counters, g_strdup(l->data), GINT_TO_POINTER(0));
		g_hash_table_insert(filer->ctx->variable.aggr2idle, g_strdup(l->data), GINT_TO_POINTER(0));
	}
	
	g_hash_table_iter_init(&iter, ht_disk2idle);
	while (g_hash_table_iter_next(&iter,&k,&v)) {
		gchar *aggr_name;
		
		aggr_name = g_hash_table_lookup(filer->ctx->fixed.disk2aggr, k);
		if (aggr_name) {
			gpointer p_count, p_sum;
			gint count, sum;

			p_count = g_hash_table_lookup(ht_disk_counters, aggr_name);
			p_sum = g_hash_table_lookup(filer->ctx->variable.aggr2idle, aggr_name);

			count = GPOINTER_TO_INT(p_count) + 1;
			sum = GPOINTER_TO_INT(p_sum) + GPOINTER_TO_INT(v);
			
			g_hash_table_insert(ht_disk_counters, aggr_name, GINT_TO_POINTER(count));
			g_hash_table_insert(filer->ctx->variable.aggr2idle, g_strdup(aggr_name), GINT_TO_POINTER(sum));
			XTRACE("aggr[%s] count[%d] sum[%d]", aggr_name, count, sum);
		}
	}

	for (l=filer->ctx->fixed.aggregates; l ; l=l->next) {
		gchar *aggr_name;
		gpointer p_count, p_sum;
		gint idle;
		
		aggr_name = l->data;
		
		p_count = g_hash_table_lookup(ht_disk_counters, aggr_name);
		p_sum = g_hash_table_lookup(filer->ctx->variable.aggr2idle, aggr_name);

		idle = 0;
		if (p_count && p_sum)
			idle = GPOINTER_TO_INT(p_sum) / GPOINTER_TO_INT(p_count);
		
		XTRACE("TOTAL : aggr[%s] sum[%d] count[%d] idle=[%d]", aggr_name,
			GPOINTER_TO_INT(p_sum), GPOINTER_TO_INT(p_count), idle);

		g_hash_table_insert(filer->ctx->variable.aggr2idle, g_strdup(aggr_name), GINT_TO_POINTER(idle));
	}

	g_hash_table_destroy(ht_disk_counters);

	/* Well... everything seems to have heppened fine! */
	LOG_RETURN(TRUE,"Success (idle=%"G_GINT64_FORMAT" out=%"G_GINT64_FORMAT" in=%"G_GINT64_FORMAT")",
		filer->ctx->variable.net_idle, out64, in64);
}

struct volume_s**
netapp_get_volumes(struct filer_s *filer, GError **err)
{
	XTRACE("Entering");
	
	if (!netapp_refresh_fixed_filer_data(filer, err)) {
		GSETERROR(err, "Uncomplete or too old filer data");
		LOG_RETURN(NULL, "Failure (uncomplete info)");
	}

	LOG_RETURN(filer->ctx->fixed.volumes,"Success");
}

struct volume_s*
netapp_get_volume(struct filer_s *filer, const char *name, GError **error)
{
	register int rc;
	struct volume_s **vol_ptr;
	struct enterprise_s *enterprise;

	XTRACE("Entering");
	
	enterprise = filer->enterprise;

	if (!netapp_refresh_fixed_filer_data(filer, error)) {
		GSETERROR(error, "Uncomplete or too old filer data");
		LOG_RETURN(NULL, "Failure (uncomplete info)");
	}

	for (vol_ptr=filer->ctx->fixed.volumes; *vol_ptr ;vol_ptr++) {
		XTRACE("Comparing [%s] to [%s]", enterprise->get_name(*vol_ptr), name);
		rc = g_ascii_strcasecmp(enterprise->get_name(*vol_ptr), name);
		if (rc == 0)
			return *vol_ptr;
	}

	LOG_RETURN(NULL, "Failure (not found)");
}

static gint 
netapp_get_volume_disk_idle(struct filer_s *filer, struct volume_s *vol, GError **err)
{
	const gchar *aggr_name;
	gpointer p_idle;
	
	aggr_name = netapp_get_volume_aggregate(vol);
	if (!aggr_name) {
		GSETERROR(err, "Aggregate unknown for volume [%s]", vol->name);
		return -1;
	}
	if (!filer->ctx->variable.aggr2idle) {
		GSETERROR(err, "Filer stats unavailable");
		return -1;
	}

	p_idle = g_hash_table_lookup(filer->ctx->variable.aggr2idle, aggr_name);
	if (!p_idle) {
		GSETERROR(err, "Aggregate [%s] not monitored (for volume [%s])", aggr_name, vol->name);
		return -1;
	}

	return GPOINTER_TO_INT(p_idle);
}

gboolean
netapp_monitor_volume(struct volume_s *vol, struct volume_statistics_s *st, GError **err)
{
	struct filer_s *filer;
	
	XTRACE("Entering [%s -> %s]", vol->path, vol->name);
	filer = vol->filer;
	
	if (!netapp_refresh_fixed_filer_data(filer, err)) {
		GSETERROR(err, "Uncomplete or too old filer data");
		LOG_RETURN(FALSE, "Failure (uncomplete info)");
	}

	/* Collect FS-dependant DATA */
	if (!snmp_get_template_int(filer->ctx->session, oid_fsUsedSpace, oid_fsUsedSpace_size,
			netapp_get_volume_id(vol), &(st->used_space), err)) {
		GSETERROR(err, "Failed to get the FS usage of this volume");
		LOG_RETURN(FALSE,"Failure (FS usage)");
	}
	if (!snmp_get_template_int(filer->ctx->session, oid_fsFreeSpace, oid_fsFreeSpace_size,
			netapp_get_volume_id(vol), &(st->free_space), err)) {
		GSETERROR(err, "Failed to get the FS availability of this volume");
		LOG_RETURN(FALSE,"Failure (FS availability)");
	}
	XTRACE("Space usage : used=%"G_GINT64_FORMAT" free=%"G_GINT64_FORMAT,
		st->used_space, st->free_space);

	/* Now get the Filer-dependant data */
	st->cpu_idle = filer->ctx->variable.cpu_idle;
	st->net_idle = filer->ctx->variable.net_idle;

	st->io_idle = netapp_get_volume_disk_idle(filer, vol, err);
	if (st->io_idle < 0) {
		GSETERROR(err, "Failed to collect the disk-idle for vol [%s]", vol->path);
		LOG_RETURN(FALSE,"Failure (disk idle)");
	}

	st->perf_idle = 100LL;

	LOG_RETURN(TRUE, "Success (net=%"G_GINT64_FORMAT" cpu=%"G_GINT64_FORMAT")", st->net_idle, st->cpu_idle);
}

/* API lifecycle */

gboolean
netapp_api_close(struct enterprise_s *e, GError **err)
{
	(void) e;
	(void) err;

	XTRACE("Entering");
	na_shutdown();
	LOG_RETURN(TRUE,"Success");
}

gboolean
netapp_api_init(struct enterprise_s *e, GError **err)
{
	gchar str_err[1024];

	(void) e;

	memset(str_err, 0x00, sizeof(str_err));
	if (!na_startup(str_err, sizeof(str_err))) {
		GSETERROR(err, "Netapp OnTap management API failure init : %.*s",
			sizeof(str_err), str_err);
		LOG_RETURN(FALSE,"Failure");
	}

	LOG_RETURN(TRUE,"Success");
}

struct enterprise_s enterprise_NETAPP = {
	"Network Appliance",
	789U,

	NULL,
	netapp_api_init,
	netapp_api_close,
	
	netapp_init_filer,
	netapp_clean_filer,
	netapp_refresh_filer_data,

	netapp_get_volumes,
	netapp_get_volume,
	netapp_monitor_volume,

	netapp_get_volume_id,
	netapp_get_volume_name,
	netapp_get_volume_type
};

