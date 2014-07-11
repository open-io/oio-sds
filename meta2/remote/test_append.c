#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "meta2.test"
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>

#include "meta2_remote.h"

static struct metacnx_ctx_s ctx;
static gchar content_path[1024];
static container_id_t cid;
static int timeout;
static content_length_t size = 131072LL;

static void
randomize_hash(GSList *chunks)
{
	unsigned int i;
	GSList *list_ci;
	chunk_info_t *ci;
	
	for (list_ci=chunks; list_ci ;list_ci=list_ci->next) {
		ci = list_ci->data;
		for (i=0; i <= sizeof(ci->hash) - sizeof(long); i += sizeof(long))
			*((long *) (ci->hash + i)) = random();
	}
}

static void
content_rollback(void)
{
	GError *local_error;

	local_error = NULL;
	if (!meta2_remote_content_rollback(&(ctx.addr), timeout, &local_error, cid, content_path)) {
		GSETERROR(&local_error, "content_commit error");
		goto label_error;
	}
	g_print("CONTENT_COMMIT: OK\n");
	return;
	
label_error:
      	fflush(stdout);
	g_printerr("ROLLBACK failed: %s\n", gerror_get_message(local_error));
	g_error_free(local_error);
	exit(1);
}

static void
content_commit(GSList *chunks)
{
	GError *local_error;

	local_error = NULL;
	randomize_hash(chunks);

	if (chunks) {
		if (!meta2_remote_chunk_commit(&(ctx.addr), timeout, &local_error, cid, content_path, chunks)) {
			GSETERROR(&local_error, "chunks_commit failure");
			goto label_error;
		}
		g_print("CHUNKS_COMMIT: OK\n");
	}

	if (!meta2_remote_content_commit(&(ctx.addr), timeout, &local_error, cid, content_path)) {
		GSETERROR(&local_error, "content_commit error");
		goto label_error;
	}
	g_print("CONTENT_COMMIT: OK\n");

	return;

label_error:
      	fflush(stdout);
	g_printerr("COMMIT failed: %s\n", gerror_get_message(local_error));
	g_error_free(local_error);
	exit(1);
}

static GSList*
replace_chunks_with_spare(GSList *chunks_nominal)
{
	GError *local_error;
	GSList *c, *chunks_spare;

	chunks_spare = NULL;
	local_error = NULL;
	for (c = chunks_nominal; c; c = c->next) {
		chunk_info_t *ci_original, *ci_spare;
		GSList *new_spare, *current_spare;

		ci_original = c->data;
		if (ci_original->position == 0 && ci_original->size == 0 && ci_original->nb == 0) {
			g_print("# spare chunk skipped\n");
			continue;
		}
		new_spare = meta2_remote_content_spare(&(ctx.addr), timeout, &local_error, cid, content_path);
		if (!new_spare) {
			GSETERROR(&local_error, "spare error");
			goto label_error;
		}
		for (current_spare = new_spare; current_spare; current_spare = current_spare->next) {
			if (!(ci_spare = current_spare->data)) {
				GSETERROR(&local_error, "Invalid (NULL) spare chunk received");
				goto label_error;
			}
			memcpy(ci_spare, ci_original, sizeof(chunk_info_t));
		}
		g_print("# got %u spare for chunk at pos=%d\n", g_slist_length(new_spare), ci_original->position);
		chunks_spare = g_slist_concat(chunks_spare, new_spare);
	}
	g_print("SPARE: OK\n");

	return chunks_spare;

label_error:
      	fflush(stdout);
	g_printerr("SPARE failed: %s\n", gerror_get_message(local_error));
	g_error_free(local_error);
	exit(1);
	return NULL;
}

static void
content_remove(gboolean commit_allowed)
{
	GError *local_error;

	g_print("# -----------------------\n");
	local_error = NULL;

	if (!meta2_remote_content_remove(&(ctx.addr), timeout, &local_error, cid, content_path)) {
		GSETERROR(&local_error, "content_remove error");
		goto label_error;
	}
	g_print("REMOVE: OK\n");
	
	if (commit_allowed)
		content_commit(NULL);
	else
		content_rollback();

	return;

label_error:
      	fflush(stdout);
	g_printerr("REMOVE failed: %s\n", gerror_get_message(local_error));
	g_error_free(local_error);
	exit(1);
}

static void
content_put(gboolean commit_allowed)
{
	GSList *chunks_nominal, *chunks_spare;
	GError *local_error;

	g_print("# -----------------------\n");

	local_error = NULL;

	chunks_nominal = meta2_remote_content_add(&(ctx.addr), timeout, &local_error, cid, content_path, size, NULL, NULL);
	if (!chunks_nominal) {
		GSETERROR(&local_error, "content_add error");
		goto label_error;
	}
	g_print("ADD: OK\n");
	
	chunks_spare = replace_chunks_with_spare(chunks_nominal);
	if (commit_allowed)
		content_commit(chunks_spare);
	else
		content_rollback();

	return;

label_error:
      	fflush(stdout);
	g_printerr("ADD failed: %s\n", gerror_get_message(local_error));
	g_error_free(local_error);
	exit(1);
}

static void
content_append(gboolean commit_allowed)
{
	GError *local_error;
	GSList *chunks_nominal, *chunks_spare;

	g_print("# -----------------------\n");

	local_error = NULL;
		
	chunks_nominal = meta2_remote_content_append(&ctx, &local_error, cid, content_path, size);
	if (!chunks_nominal) {
		GSETERROR(&local_error, "append error");
		goto label_error;
	}
	g_print("APPEND: OK\n");
	metacnx_close(&ctx);

	/*replaces each chunk with a spare chunk */
	chunks_spare = replace_chunks_with_spare(chunks_nominal);
	if (commit_allowed)
		content_commit(chunks_spare);
	else
		content_rollback();

	return ;
label_error:
      	fflush(stdout);
	g_printerr("APPEND failed: %s\n", gerror_get_message(local_error));
	g_error_free(local_error);
	exit(1);
}

static void
parse_options(int argc, char ** args)
{
	GError *local_error;
	const gchar *str_host;
	const gchar *str_port;
	const gchar *str_cname;

	if (argc != 4) {
		g_printerr("Usage: %s <host> <port> <cname>\n", args[0]);
		abort();
	}

	local_error = NULL;
	str_host = args[1];
	str_port = args[2];
	str_cname = args[3];
	srandom(time(0));

	/*META2 reference configuration*/
	memset(&ctx, 0x00, sizeof(ctx));
	ctx.fd = -1;
	timeout = ctx.timeout.req = ctx.timeout.cnx = 4096;
	if (!metacnx_init(&ctx, str_host, atoi(str_port), &local_error)) {
		g_printerr("Config: ERROR %s\n", gerror_get_message(local_error));
		g_error_free(local_error);
		exit(-1);
	}
	
	/*Container/content configuration*/
	memset(cid, 0x00, sizeof(container_id_t));
	memset(content_path, 0x00, sizeof(content_path));

	meta1_name2hash(cid, NULL, str_cname);
	g_snprintf(content_path, sizeof(content_path), "content.%d.%ld.%ld", getpid(), time(0), random());

	g_print("Config: OK\n");
}

int
main(int argc, char **args)
{
	GError *local_error;
	
	parse_options(argc, args);
	
	local_error = NULL;
	if (!meta2_remote_container_open(&(ctx.addr), timeout, &local_error, cid)) {
		GSETERROR(&local_error, "open error");
		goto label_error;
	}
	g_print("OPEN: OK\n");

	content_put(TRUE);
	content_append(TRUE);
	content_remove(TRUE);
	
	content_put(TRUE);
	content_append(FALSE);
	content_remove(TRUE);
	
	if (!meta2_remote_container_close(&(ctx.addr), timeout, &local_error, cid)) {
		GSETERROR(&local_error, "close error");
		goto label_error;
	}
	g_print("CLOSE: OK\n");

	return 0;
label_error:
      	fflush(stdout);
	g_printerr("Failed: %s\n", gerror_get_message(local_error));
	g_error_free(local_error);
	return 1;
}
