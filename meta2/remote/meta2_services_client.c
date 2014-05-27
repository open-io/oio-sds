#include <stdlib.h>
#include <string.h>
#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include "meta2_services_remote.h"
#include "meta2_remote.h"

static struct metacnx_ctx_s cnx;
static container_id_t cid;
static char service_name[LIMIT_LENGTH_SRVTYPE];

static void
_gfree_list(GSList **l)
{
	if (l) {
		if (*l) {
			g_slist_foreach(*l, g_free1, NULL);
			g_slist_free(*l);
		}
		*l = NULL;
	}
}

static void
_display_strlist( const gchar *prefix, GSList *list)
{
	GSList *l;
	if (list) {
		for (l=list; l ;l=l->next) {
			if (!l->data)
				continue;
			g_printerr("%s%s\r\n", prefix, (gchar*) l->data);
		}
	} else
		g_printerr("%s***nothing***\r\n", prefix);
}

static GSList*
build_paths_list(int argc, char ** args)
{
	int i;
	char **pArg;
	GSList *paths;

	paths = NULL;
	for (pArg=args,i=0; *pArg && i<argc ;pArg++,i++)
		paths = g_slist_prepend(paths,*pArg);

	return paths;
}

static int
test_flush(void)
{
	GError *error_local;
	GSList *services_used, *remaining_services;
	
	error_local = NULL;
	if (!meta2_remote_container_open(&(cnx.addr), cnx.timeout.req, &error_local, cid)) {
		g_printerr("Failed to open the distant container : %s\r\n", gerror_get_message(error_local));
		g_clear_error(&error_local);
		return 0;
	}

	services_used = NULL;
	if (!meta2_remote_service_flush(&cnx, cid, service_name, &services_used, &error_local)) {
		g_printerr("Container flush failed for service type [%s] : %s\r\n",
			service_name, gerror_get_message(error_local));
		g_clear_error(&error_local);
		return 0;
	}

	remaining_services = meta2_remote_service_get_all_used(&cnx, cid, service_name, &error_local);
	if (error_local) {
		_gfree_list(&services_used);
		g_printerr("Failed to list the services of type [%s] : %s\r\n",
			service_name, gerror_get_message(error_local));
		g_clear_error(&error_local);
		return 0;
	}
	if (remaining_services) {
		g_printerr("Bad container flsh, some services remain [%d]\r\n", g_slist_length(remaining_services));
		_gfree_list(&remaining_services);
		_gfree_list(&services_used);
		return 0;
	}
	
	return 1;
}

static int
test_add_service(int argc, char ** args, int validation)
{
	GSList *really_removed=NULL, *commit_failed=NULL, *services_used=NULL;
	struct service_info_s *si;
	GSList *paths;
	GError *err;

	if (argc<1) {
		g_printerr("Failed to add anything : expecting argument\r\n");
		abort();
	}

	err = NULL;
	if (!meta2_remote_container_open(&(cnx.addr), cnx.timeout.req, &err, cid)) {
		g_printerr("Failed to open the distant container : %s\r\n", gerror_get_message(err));
		g_clear_error(&err);
		return 0;
	}

	paths = build_paths_list(argc,args);
	si = meta2_remote_service_add_contents(&cnx, cid, service_name, paths, &err);
	_display_strlist("\tAdd wanted: ", paths);
	if (si == NULL) {
		g_printerr("Failed to insert a path : %s\r\n", gerror_get_message(err));
	} else {
		gchar str_addr[128];

		addr_info_to_string(&(si->addr), str_addr, sizeof(str_addr));
		g_printerr("Service found: %s\r\n", str_addr);
	}

	if (validation) {
		status_t rc0, rc1, rc2;
		
		/* COMMIT */
		rc0 = meta2_remote_service_commit_contents(&cnx,cid,service_name,paths,&commit_failed,&err);
		_display_strlist("\tCommit wanted: ", paths);
		_display_strlist("\tCommit succeeded: ", commit_failed); _gfree_list(&commit_failed);
		g_printerr("RESULT : %s\r\n", rc0 ? "ok" : gerror_get_message(err));

		if (rc0) {
			GError *e;
			gboolean rc_local;

			/* Second-COMMIT */
			e = NULL;
			rc_local = meta2_remote_service_commit_contents(&cnx,cid,service_name,paths,&commit_failed,&e);
			_display_strlist("\tSecond Commit wanted: ", paths);
			_display_strlist("\tSecond Commit failed: ", commit_failed);
			_gfree_list(&commit_failed);
			g_printerr("Second Commit RESULT : %s\r\n", rc_local ? "ok" : gerror_get_message(e));
		}

		/* DELETE */
		rc1 = meta2_remote_service_delete_contents(&cnx, cid, service_name, paths, &really_removed, &services_used, &err);
		_display_strlist("\tDelete wanted: ", paths);
		_display_strlist("\tservices used: ", services_used);
		_display_strlist("\tcontent removed : ", really_removed);
		_gfree_list(&services_used);
		_gfree_list(&really_removed);
		g_printerr("RESULT : %s\r\n", rc1 ? "ok" : gerror_get_message(err));

		/* COMMIT */
		rc2 = meta2_remote_service_commit_contents(&cnx,cid,service_name,paths,&commit_failed,&err);
		_display_strlist("\tCommit wanted: ", paths);
		_display_strlist("\tCommit succeeded: ", commit_failed);
		_gfree_list(&commit_failed);
		g_printerr("RESULT : %s\r\n", rc2 ? "ok" : gerror_get_message(err));

		if (!rc0 || !rc1 || !rc2)
			goto error_label;
	}
	else {
		status_t rc0, rc1, rc2;

		rc0 = rc1 = rc2 = ~0;

		/* ROLLBACK */
		rc0 = meta2_remote_service_rollback_contents(&cnx,cid,service_name,paths,&commit_failed,&err);
		_display_strlist("\tRollback wanted: ", paths);
		_display_strlist("\tRollback failed: ", commit_failed); _gfree_list(&commit_failed);
		g_printerr("RESULT : %s\r\n", rc0 ? "ok" : gerror_get_message(err));
		
		if (rc0) {
			GError *e;
			gboolean rc_local;

			/* Second-COMMIT */
			e = NULL;
			rc_local = meta2_remote_service_rollback_contents(&cnx,cid,service_name,paths,&commit_failed,&e);
			_display_strlist("\tSecond Rollback wanted: ", paths);
			_display_strlist("\tSecond Rollback failed: ", commit_failed); _gfree_list(&commit_failed);
			g_printerr("Second Rollback RESULT : %s\r\n", rc_local ? "ok" : gerror_get_message(e));
		}

		/* DELETE */
		rc1 = meta2_remote_service_delete_contents(&cnx, cid, service_name, paths, &really_removed, &services_used, &err);
		_display_strlist("\tDelete wanted: ", paths);
		_display_strlist("\tservices used: ", services_used);
		_display_strlist("\tcontent removed : ", really_removed);
		g_printerr("RESULT : %s\r\n", rc1 ? "ok" : gerror_get_message(err));

		if (services_used || really_removed) {
			g_printerr("ADD+ROLLBACK content should not be found\n");
			rc2 = 0;
		}
		
		if (!rc0 || !rc1 || !rc2)
			goto error_label;
	}

	meta2_remote_container_close_in_fd(cnx.fd, cnx.timeout.req, NULL, cid);
	return 1;
error_label:
	g_slist_free(paths);
	meta2_remote_container_close_in_fd(cnx.fd, cnx.timeout.req, NULL, cid);
	g_clear_error(&err);
	return 0;
}

static int
init_static_vars(int argc, char ** args)
{
	GError *err;
	
	if (argc<4) {
		g_printerr("Failed to init the address and container_id : 4 tokens expected (IP, PORT, CONTAINER_ID, SERVICE_NAME)\r\n");
		abort();
	}

	err = NULL;
	if (!metacnx_init(&cnx, args[0], atoi(args[1]), &err)) {
		g_printerr("Failed to init address : %s\r\n", gerror_get_message(err));
		abort();
	}
	cnx.timeout.req = cnx.timeout.cnx = 5000;

	if (!container_id_hex2bin(args[2],strlen(args[2]),&cid,&err)) {
		g_printerr("Failed to read the container_id : %s\r\n", gerror_get_message(err));
		abort();
	} else {
		gchar str_cid[STRLEN_CONTAINERID];
		container_id_to_string(cid,str_cid,sizeof(str_cid));
		g_printerr("Using container [%s]\n", str_cid);
	}

	g_strlcpy(service_name,args[3],sizeof(service_name));

	return 4;
}

int
main (int argc, char ** args)
{
	int args_offset;

	if (log4c_init()) {
		g_printerr("Failed to init log4c\r\n");
		abort();
	}

	args_offset = 1;
	args_offset += init_static_vars(argc-args_offset,args+args_offset);
	
	if (test_add_service(argc-args_offset,args+args_offset, FALSE)) {
		NOTICE("%s : ok", "test_add_service(rollback)");
	} else {
		NOTICE("%s : KO", "test_add_service(rollback)");
	}

	if (test_add_service(argc-args_offset,args+args_offset, TRUE)) {
		NOTICE("%s : ok", "test_add_service(commit)");
	} else {
		NOTICE("%s : KO", "test_add_service(commit)");
	}

	if (test_flush()) {
		NOTICE("%s : ok", "test_flush()");
	} else {
		NOTICE("%s : KO", "test_flush()");
	}

	return 0;
}
