#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "meta2.remote.client"
#endif

#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "meta2_remote.h"


static addr_info_t meta2addr;
static gint timeOut = 2000;
static gchar *remotePath=NULL;

static content_length_t remoteSize = 0;
static container_id_t id;

static gint
doCmd (gchar *cmd, GError **err)
{
	if (0 == strcasecmp("CREATE", cmd))
	{
		if (!meta2_remote_container_create(&meta2addr, timeOut, err, id, "test de nom de conteneur"))
			goto errorLabel;
	}
	
	else if (0 == strcasecmp("DESTROY", cmd))
	{
		if (!meta2_remote_container_destroy(&meta2addr, timeOut, err, id))
			goto errorLabel;
	}

	else if (0 == strcasecmp("OPEN", cmd))
	{
		if (!meta2_remote_container_open(&meta2addr, timeOut, err, id))
			goto errorLabel;
	}

	else if (0 == strcasecmp("CLOSE", cmd))
	{
		if (!meta2_remote_container_close(&meta2addr, timeOut, err, id))
			goto errorLabel;
	}

	else if (0 == strcasecmp("ADD", cmd))
	{
		GSList *list, *l;
		if (!(list = meta2_remote_content_add(&meta2addr, timeOut, err, id, remotePath, remoteSize, NULL, NULL)))
			goto errorLabel;
		for (l=list; l ;l=l->next) {
			static gchar printBuf[4096];
			chunk_info_to_string((chunk_info_t*)l->data, printBuf, 4096);
			g_print("> %s\r\n", printBuf);
		}
		g_slist_foreach(list,g_free1,NULL);
		g_slist_foreach(list,g_free1,NULL);
		g_slist_free(list);
	}

	else if (0 == strcasecmp("COMMIT", cmd))
	{
		if (!meta2_remote_content_commit (&meta2addr, timeOut, err, id, remotePath))
			goto errorLabel;
	}

	else if (0 == strcasecmp("ROLLBACK", cmd))
	{
		if (!meta2_remote_content_rollback(&meta2addr, timeOut, err, id, remotePath))
			goto errorLabel;
	}

	else if (0 == strcasecmp("RETRIEVE", cmd))
	{
		GSList *list, *l;
		if (!(list = meta2_remote_content_retrieve(&meta2addr, timeOut, err, id, remotePath)))
			goto errorLabel;
		for (l=list; l ;l=l->next) {
			static gchar printBuf[4096];
			chunk_info_to_string((chunk_info_t*)l->data, printBuf, 4096);
			g_print("> %s\r\n", printBuf);
		}
		g_slist_foreach(list,g_free1,NULL);
		g_slist_free(list);
	}

	else if (0 == strcasecmp("FREEZE", cmd))
	{
		if (!meta2_remote_container_set_flag (&meta2addr, timeOut, err, id, REMOTECONTAINER_FLAG_FROZEN))
			goto errorLabel;
	}

	else if (0 == strcasecmp("UNAVAILABLE", cmd))
	{
		if (!meta2_remote_container_set_flag (&meta2addr, timeOut, err, id, REMOTECONTAINER_FLAG_DISABLED))
			goto errorLabel;
	}

	else if (0 == strcasecmp("ENABLE", cmd))
	{
		if (!meta2_remote_container_set_flag (&meta2addr, timeOut, err, id, REMOTECONTAINER_FLAG_OK))
			goto errorLabel;
	}

	else if (0 == strcasecmp("LIST", cmd))
	{
		GSList *list, *l;
		if (!(list = meta2_remote_container_list (&meta2addr, timeOut, err, id))) {
			if (err && *err)
				goto errorLabel;
			INFO("no content");
		}
		for (l=list; l ;l=l->next) {
			static gchar printBuf[4096];
			path_info_to_string((path_info_t*)l->data, printBuf, sizeof(printBuf));
			g_print("> %s\n", printBuf);
		}
		g_slist_foreach (list, g_free1, NULL);
		g_slist_free(list);
	}
	
	else if (0 == strcasecmp("REMOVE", cmd))
	{
		if (!meta2_remote_content_remove (&meta2addr, timeOut, err, id, remotePath))
			goto errorLabel;
	}

	else if (0 == strcasecmp("REPAIR",cmd))
	{
		if (!meta2raw_remote_mark_container_repaired(&meta2addr, timeOut, err, id))
			goto errorLabel;
	}

	else if (0 == strcasecmp("INFO", cmd))
	{
		GHashTable *ht = meta2_remote_info_with_addr( &meta2addr, timeOut, err );
		if (!ht)
			goto errorLabel;
		g_print("META2 information: NS=[%s] CONFIGURATION=[%s]\n",
			(char*)g_hash_table_lookup(ht, "NS"), (char*)g_hash_table_lookup(ht, "CFG"));
		g_hash_table_destroy( ht );
	}

	else if (0 == strcasecmp("ADMIN", cmd))
	{
		GHashTable *ht;
		GHashTableIter iterator;
		gpointer k, v;
		struct metacnx_ctx_s ctx;
		
		metacnx_clear( &ctx );
		memcpy( &(ctx.addr), &meta2addr, sizeof(addr_info_t));
		ctx.timeout.req = timeOut;
		ctx.timeout.cnx = timeOut;
		
		ht = meta2raw_remote_get_admin_entries( &ctx, err, id );
		if (!ht)
			goto errorLabel;
		g_hash_table_iter_init(&iterator,ht);
		g_print("Container admin table:\n");
		while (g_hash_table_iter_next(&iterator,&k,&v))
			g_print("\t[%s]:[%s];\n", (gchar*)k, (gchar*)v);
		g_print("End of container admin table.\n");
		g_hash_table_destroy( ht );
	}

	else
	{
		GSETERROR(err, "<%s> command not found", __FUNCTION__);
		goto errorLabel;
	}

	return 1;

errorLabel:
	GSETERROR(err, "<%s> cannot execute the command %s", __FUNCTION__, cmd);
	return 0;
}


int
main (int argc, char ** args)
{
	if (log4c_init())
		g_error("Cannot init log4c");

	if (argc < 6) {
		ERROR("usage: %s HOST:PORT PATH SIZE CONTAINER_ID ACTION\r\n", args[0]);
		return 1;
	}

	GError *err = NULL;
	memset (&meta2addr, 0x00, sizeof(addr_info_t));
	if (!l4_address_init_with_url(&meta2addr, args[1], &err)) {
		return -1;
	}

	/*connect to the meta2 address*/
	remotePath = args[2];
	remoteSize = g_ascii_strtoull(args[3],NULL,10);

	DEBUG("size=%"G_GINT64_FORMAT"/%"G_GUINT64_FORMAT, remoteSize, (guint64)remoteSize);
	g_assert (container_id_hex2bin (args[4], strlen(args[4]), &id, &err));

	for (int i=5; i<argc ;i++) {
		err = NULL;
		if (!doCmd(args[i], &err))
			ERROR("Cannot execute the command: %s", err?err->message:"?");
		if (err)
			g_clear_error(&err);
	}

	return 0;
}

