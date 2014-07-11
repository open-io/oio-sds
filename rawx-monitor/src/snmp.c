#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "vol.monitor"
#endif

#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "filer_monitor.h"

static inline void
_gpa_free_all(GPtrArray *gpa)
{
	guint i;
	for (i=0; i<gpa->len ;i++)
		g_free(gpa->pdata[i]);
	g_ptr_array_free(gpa, TRUE);
}

size_t 
oid_snprint(char *dst, size_t dst_size, oid *name, size_t name_len)
{
	size_t i, offset = 0;
	memset(dst, 0x00, dst_size);
	for (i=0; i<name_len && offset<dst_size ;i++)
		offset += g_snprintf(dst+offset, dst_size-offset, ".%lu", name[i]);
	return offset;
}

size_t
snmp_get_error(char *dst, size_t dst_size, netsnmp_session *session)
{
	size_t len;
	char *str = NULL;

	snmp_error(session, &errno, &snmp_errno, &str);
	memset(dst, 0x00, dst_size);
	len = g_strlcpy(dst, str, dst_size-1);
	free(str);
	return len;
}

struct int_mapping_s**
snmp_get_integers(netsnmp_session *session, oid *prefix, size_t prefix_size, GError **err)
{
	gchar str_oid[MAX_OID_LEN * 9];
	gchar str_snmp_error[512];
	GError *error_local = NULL;
	GPtrArray *gpa;
	netsnmp_pdu *request, *response;
	oid last_oid[MAX_OID_LEN];
	size_t last_oid_size;
	int status, vol_index;

	oid_snprint(str_oid, sizeof(str_oid), prefix, prefix_size);
	TRACE("Walking the subtree of oid=[%s]", str_oid);

	memset(last_oid, 0x00, sizeof(last_oid));
	last_oid_size = prefix_size;
	memcpy(last_oid, prefix, prefix_size * sizeof(oid));

	vol_index = 0;
	gpa = g_ptr_array_sized_new(1);
	for (;;) {
		netsnmp_variable_list *vars;

		response = NULL;
		request = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(request, last_oid, last_oid_size);

		status = snmp_synch_response(session, request, &response);
		if (status != STAT_SUCCESS) {
			snmp_get_error(str_snmp_error, sizeof(str_snmp_error), session);
			GSETERROR(&error_local, "SNMP network error : %s", str_snmp_error);
			snmp_free_pdu(response);
			TRACE("Network error : %s", str_snmp_error);
			goto label_error;
		}
		if (response->errstat != SNMP_ERR_NOERROR) {
			snmp_get_error(str_snmp_error, sizeof(str_snmp_error), session);
			GSETERROR(&error_local, "SNMP server error : %s", str_snmp_error);
			snmp_free_pdu(response);
			TRACE("Server error : %ld %s", response->errstat, str_snmp_error);
			goto label_error;
		}
		
		for (vars=response->variables; vars ;vars=vars->next_variable) {

			memcpy(last_oid, vars->name, vars->name_length * sizeof(oid));
			last_oid_size = vars->name_length;
			oid_snprint(str_oid, sizeof(str_oid), vars->name, vars->name_length);
			
			if (!(last_oid_size == prefix_size + 1
				&& 0 == memcmp(last_oid, prefix, prefix_size * sizeof(oid)))) {
				TRACE("OID=[%s] end of subtree matched", str_oid);
				snmp_free_pdu(response);
				goto exit_loop;
			}

			if (vars->type == ASN_INTEGER && vars->val.integer) {
				struct int_mapping_s *im;
				im = calloc(1, sizeof(struct int_mapping_s));
				im->id = vol_index ++;
				im->i64 = *(vars->val.integer);
				g_ptr_array_add(gpa, im);
				DEBUG("OID=[%s] int=[%"G_GINT64_FORMAT"]", str_oid, im->i64);
			}
			else
				DEBUG("OID=[%s] is not an integer value (type=%x)", str_oid, vars->type);
		}

		snmp_free_pdu(response);
	}

exit_loop:
	if (error_local)
		g_clear_error(&error_local);

	g_ptr_array_add(gpa, NULL);
	TRACE("%d integer mappings have been found", g_strv_length((gchar**)gpa->pdata));
	return (struct int_mapping_s**) g_ptr_array_free(gpa, FALSE);

label_error:
	if (err)
		*err = error_local;
	else if (!error_local)
		ERROR("Could not get all the volume mappings : unknown error");
	else {
		ERROR("Could not get all the volume mappings : %s", error_local->message);
		g_clear_error(&error_local);
	}
	_gpa_free_all(gpa);
	XTRACE("Failure");
	return NULL;
}

struct string_mapping_s**
snmp_get_strings(netsnmp_session *session, oid *prefix, size_t prefix_size, GError **err)
{
	gchar str_oid[MAX_OID_LEN * 9];
	gchar str_snmp_error[512];
	GError *error_local = NULL;
	GPtrArray *gpa;
	netsnmp_pdu *request, *response;
	oid last_oid[MAX_OID_LEN];
	size_t last_oid_size;
	int status, vol_index;

	oid_snprint(str_oid, sizeof(str_oid), prefix, prefix_size);
	TRACE("Walking the subtree of oid=[%s]", str_oid);

	memset(last_oid, 0x00, sizeof(last_oid));
	last_oid_size = prefix_size;
	memcpy(last_oid, prefix, prefix_size * sizeof(oid));

	vol_index = 0;
	gpa = g_ptr_array_new();
	for (;;) {
		netsnmp_variable_list *vars;

		response = NULL;
		request = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(request, last_oid, last_oid_size);

		status = snmp_synch_response(session, request, &response);
		if (status != STAT_SUCCESS) {
			snmp_get_error(str_snmp_error, sizeof(str_snmp_error), session);
			GSETERROR(&error_local, "SNMP network error : %s", str_snmp_error);
			snmp_free_pdu(response);
			TRACE("Network error : %s", str_snmp_error);
			goto label_error;
		}
		if (response->errstat != SNMP_ERR_NOERROR) {
			snmp_get_error(str_snmp_error, sizeof(str_snmp_error), session);
			GSETERROR(&error_local, "SNMP server error : %s", str_snmp_error);
			snmp_free_pdu(response);
			TRACE("Server error : %ld %s", response->errstat, str_snmp_error);
			goto label_error;
		}
		
		for (vars=response->variables; vars ;vars=vars->next_variable) {

			memcpy(last_oid, vars->name, vars->name_length * sizeof(oid));
			last_oid_size = vars->name_length;
	        	oid_snprint(str_oid, sizeof(str_oid), last_oid, last_oid_size);

			if (!(last_oid_size == prefix_size + 1
				&& 0 == memcmp(last_oid, prefix, prefix_size * sizeof(oid)))) {
				TRACE("OID=[%s] end of subtree matched", str_oid);
				snmp_free_pdu(response);
				goto exit_loop;
			}

			oid_snprint(str_oid, sizeof(str_oid), vars->name, vars->name_length);
			if (vars->type == ASN_OCTET_STR) {
				struct string_mapping_s *vm;
				vm = g_try_malloc0(sizeof(struct string_mapping_s));
				if (!vm)
					abort();
				vm->id = vol_index ++;

				int val_len_int = vars->val_len;
				g_snprintf(vm->name, sizeof(vm->name), "%.*s", val_len_int, vars->val.string);

				g_ptr_array_add(gpa, vm);
				DEBUG("OID=[%s] str=[%s]", str_oid, vm->name);
			}
			else
				DEBUG("OID=[%s] is not a string (type=%x)", str_oid, vars->type);
		}

		snmp_free_pdu(response);
	}

exit_loop:
	if (error_local)
		g_error_free(error_local);

	/*g_ptr_array_set_size(gpa, gpa->len + 1);*/
	g_ptr_array_add(gpa, NULL);
	TRACE("%d string mappings have been found", g_strv_length((gchar**)gpa->pdata));
	return (struct string_mapping_s**) g_ptr_array_free(gpa, FALSE);

label_error:
	if (err)
		*err = error_local;
	else if (!error_local)
		ERROR("Could not get all the volume mappings : unknown error");
	else {
		ERROR("Could not get all the volume mappings : %s", error_local->message);
		g_error_free(error_local);
	}
	_gpa_free_all(gpa);
	XTRACE("Failure");
	return NULL;
}

int
snmp_get_enterprise_code(netsnmp_session *session, oid *code, GError **err)
{
	static oid oid_prefix_enterprise[] = {1U,3U,6U,1U,4U,1U};
	static size_t oid_prefix_enterprise_len = sizeof(oid_prefix_enterprise)/sizeof(oid);

	gchar str_snmp_error[512];
	struct variable_list *vars;
	netsnmp_pdu *pdu, *response;
	int status, count = 0;

	pdu = response = NULL;

	pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
	if (!pdu) {
		GSETERROR(err, "Memory allocation failure");
		return 0;
	}

	snmp_add_null_var(pdu, oid_prefix_enterprise, oid_prefix_enterprise_len);

	/* synchronous request */
	status = snmp_synch_response(session, pdu, &response);
	if (STAT_SUCCESS != status) {
		snmp_free_pdu(response);
		snmp_get_error(str_snmp_error, sizeof(str_snmp_error), session);
		GSETERROR(err, "SNMP network error : %s", str_snmp_error);
		return 0;
	}
	if (response->errstat != SNMP_ERR_NOERROR) {
		snmp_free_pdu(response);
		snmp_get_error(str_snmp_error, sizeof(str_snmp_error), session);
		GSETERROR(err, "SNMP applicative error : %s", str_snmp_error);
		return 0;
	}

	/* we should have one and only one variable in the answer.
	 * Nevermind the variable type, we only considerits OID.
	 */
	for(vars = response->variables; vars ;vars = vars->next_variable) {
		char str_oid[MAX_OID_LEN * 9];
		if (count) {
			GSETERROR(err, "Too many variables in the answer");
			snmp_free_pdu(response);
			return 0;
		}

		if (vars->name_length == oid_prefix_enterprise_len && 0==memcmp(vars->name,oid_prefix_enterprise,oid_prefix_enterprise_len)) {
			GSETERROR(err, "No private/enterprise MIB extension");
			snmp_free_pdu(response);
			return 0;
		}

		oid_snprint(str_oid, sizeof(str_oid), vars->name, vars->name_length);
		DEBUG("OID found = %s (length=%"G_GSIZE_FORMAT")", str_oid, vars->name_length);

		if (vars->name_length < oid_prefix_enterprise_len) {
			DEBUG("OID too short!");
			continue;
		}

		*code = vars->name[oid_prefix_enterprise_len];
		DEBUG("OID retained : %lu", *code);
		count++;
	}

	snmp_free_pdu(response);
	XTRACE("Success");
	return 1;
}

gboolean
snmp_get_int(netsnmp_session *s, oid *what, size_t what_len, gint64 *i64, GError **err)
{
	gchar str_snmp_error[512];
	struct variable_list *vars;
	netsnmp_pdu *pdu, *response;
	int count, status;
	gchar str_oid[MAX_OID_LEN * 9];
	
	oid_snprint(str_oid, sizeof(str_oid), what, what_len);
	XTRACE("Entering OID=[%s]", str_oid);
	pdu = response = NULL;
	pdu = snmp_pdu_create(SNMP_MSG_GET);
	if (!pdu) {
		GSETERROR(err, "Memory allocation failure");
		return FALSE;
	}
	snmp_add_null_var(pdu, what, what_len);

	/* synchronous request */
	status = snmp_synch_response(s, pdu, &response);
	if (STAT_SUCCESS != status) {
		snmp_free_pdu(response);
		snmp_get_error(str_snmp_error, sizeof(str_snmp_error), s);
		GSETERROR(err, "SNMP network error : %s", str_snmp_error);
		return FALSE;
	}
	if (response->errstat != SNMP_ERR_NOERROR) {
		snmp_free_pdu(response);
		snmp_get_error(str_snmp_error, sizeof(str_snmp_error), s);
		GSETERROR(err, "SNMP applicative error : %s", str_snmp_error);
		return FALSE;
	}

	count = 0;
	for(vars = response->variables; vars ;vars = vars->next_variable) {
		if (count) {
			ERROR("Too many variables in the answer");
			snmp_free_pdu(response);
			return FALSE;
		}

		oid_snprint(str_oid, sizeof(str_oid), vars->name, vars->name_length);
		DEBUG("OID found = %s (length=%"G_GSIZE_FORMAT")", str_oid, vars->name_length);

		*i64 = *(vars->val.integer);
		DEBUG("Value retained : %"G_GINT64_FORMAT, *i64);
		count++;
	}

	snmp_free_pdu(response);
	XTRACE("Success");
	return TRUE;
}

gboolean
snmp_get_template_int(netsnmp_session *s, oid *what, size_t what_len, oid which, gint64 *i64, GError **err)
{
	oid what_full[MAX_OID_LEN];
	
	memset(what_full, 0x00, sizeof(what_full));
	memcpy(what_full, what, sizeof(oid) * what_len);
	what_full[what_len] = which;
	return snmp_get_int(s, what_full, what_len+1, i64, err);
}

gboolean
snmp_get_interface_index(netsnmp_session *s, oid *itfIndex, GError **err)
{
	static oid oid_prefix_itfIndex[] = {1,3,6,1,2,1,4,20,1,2};
	static size_t oid_prefix_len_itfIndex = sizeof(oid_prefix_itfIndex)/sizeof(oid);

	gint64 i64;
	oid oid_itfIndex[MAX_OID_LEN];

	XTRACE("Entering");
	memset(oid_itfIndex, 0x00, sizeof(oid_itfIndex));
	memcpy(oid_itfIndex, oid_prefix_itfIndex, oid_prefix_len_itfIndex * sizeof(oid));
	do {
		gchar **tokens, *ptr;

		ptr = strchr(s->peername, ':');
		tokens = g_strsplit(ptr ? ptr : s->peername,".", 5);
		oid_itfIndex[oid_prefix_len_itfIndex+0] = atoi(tokens[0]);
		oid_itfIndex[oid_prefix_len_itfIndex+1] = atoi(tokens[1]);
		oid_itfIndex[oid_prefix_len_itfIndex+2] = atoi(tokens[2]);
		oid_itfIndex[oid_prefix_len_itfIndex+3] = atoi(tokens[3]);
		g_strfreev(tokens);
	} while (0);
	
	if (snmp_get_int(s, oid_itfIndex, oid_prefix_len_itfIndex+4, &i64, err)) {
		*itfIndex = i64;
		XTRACE("Success");
		return TRUE;
	}

	GSETERROR(err, "SNMP error");
	XTRACE("Failure");
	return FALSE;
}

gboolean
snmp_get_interface_speed(netsnmp_session *s, oid itfIndex, gint64 *itfSpeed, GError **err)
{
	static oid oid_prefix_itfSpeed[] = {1,3,6,1,2,1,2,2,1,5};
	static size_t oid_prefix_len_itfSpeed = sizeof(oid_prefix_itfSpeed)/sizeof(oid);

        gint64 i64;
	oid oid_itfSpeed[MAX_OID_LEN];
	
	memset(oid_itfSpeed, 0x00, sizeof(oid_itfSpeed));
	memcpy(oid_itfSpeed, oid_prefix_itfSpeed, oid_prefix_len_itfSpeed * sizeof(oid));
	oid_itfSpeed[oid_prefix_len_itfSpeed] = itfIndex;
	
	if (snmp_get_int(s, oid_itfSpeed, oid_prefix_len_itfSpeed+1, &i64, err)) {
		*itfSpeed = i64;
		XTRACE("Success");
		return TRUE;
	}

	GSETERROR(err, "SNMP error");
	XTRACE("Failure");
	return FALSE;
}

netsnmp_session*
snmp_init(netsnmp_session *base_session, gchar *host, struct snmp_auth_s *snmp_auth,
        GError **err)
{
	netsnmp_session *session = NULL;

	if (!host || !snmp_auth) {
		GSETERROR(err, "Invalid parameter (%p %p)", host, snmp_auth);
		return NULL;
	}

	/* Creates a SNMP session */
	switch (snmp_auth->version) {
	case 1:
		base_session->version = SNMP_VERSION_1;
		break;
	case 2:
		base_session->version = SNMP_VERSION_2c;
		base_session->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
		base_session->community = (u_char*)snmp_auth->community;
		base_session->community_len = strlen((char*) base_session->community);
		break;
	case 3:
		base_session->version = SNMP_VERSION_3;
		base_session->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
		base_session->community = (u_char*)snmp_auth->community;
		base_session->community_len = strlen((char*)base_session->community);
		base_session->securityName = snmp_auth->security_name;
		base_session->securityNameLen = strlen(base_session->securityName);
		break;
	default:
		GSETERROR(err, "Invalid SNMP version (1, 2 or 3 allowed)");
		return NULL;
	}

	base_session->peername = host;

	session = snmp_open(base_session);
	if (!session) {
		GSETERROR(err, "Failed to open the SNMP session to [%s]", host);
		return NULL;
	}

	return session;
}

