#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "rules_motor"
#endif

#include <glib.h>

#include "./motor.h"

PyThreadState * mainThreadState = NULL;

void
motor_env_init()
{
	if(!Py_IsInitialized())
		Py_Initialize();

	if (motor_env == NULL)
		motor_env = g_malloc0(sizeof(struct rules_motor_env_s));
}

void
motor_env_init_v_multi_thread()
{
	motor_env_init();
	if(!PyEval_ThreadsInitialized())
		PyEval_InitThreads();
	mainThreadState = PyThreadState_Get();
	PyEval_ReleaseLock();
}

int
get_and_load_rules(struct rules_motor_env_s** me, const gchar *ns_name){
	int rc;
	GByteArray *mod_in_string = NULL;
	PyObject *py_main = NULL;
	GError *err = NULL;

	/* Free previous module and function in 'me' */
	if ((*me)->py_function != NULL) {
		Py_XDECREF((*me)->py_function);
		(*me)->py_function = NULL;
	}
	if ((*me)->py_module != NULL) {
		Py_XDECREF((*me)->py_module);
		(*me)->py_module = NULL;
	}

	/* Get rule script from conscience */
	mod_in_string = namespace_get_rules(ns_name, CHUNK_CRAWLER, &err);
	if(mod_in_string == NULL){
		ERROR("Failed to fetch rules : %s", err->message);
		g_clear_error (&err);
		return -1;
	}
	PyRun_SimpleString("import imp");
	PyRun_SimpleString("rules_mod = imp.new_module('rules_mod')");
	py_main = PyImport_AddModule("__main__");

	rc = PyModule_AddStringConstant(py_main, "mod_in_string", (char *)mod_in_string->data);
	g_byte_array_free(mod_in_string, TRUE);
	if(rc == -1){
		ERROR("Failed to import rules(GByteArray) into python environment");
		return -1;
	}

	PyRun_SimpleString("exec mod_in_string in rules_mod.__dict__");

	(*me)->py_module = PyObject_GetAttrString(py_main, "rules_mod");
	if((*me)->py_module == NULL){
		ERROR("Failed to load python module");
		return -1;
	}

	(*me)->py_function = PyObject_GetAttrString((*me)->py_module, "main");
	if((*me)->py_function == NULL){
		ERROR("Failed to get python function hook");
		return -1;
	}

	return 1;
}

int
update_rules(struct rules_motor_env_s** me, const gchar *ns_name){
	if(((*me)->py_function != NULL) && (*me)->py_module != NULL){
		if(!is_time_to_reload_rules())
			return 0;
	}
	return get_and_load_rules(me, ns_name);
}

gboolean
is_time_to_reload_rules(){
	static time_t last_reload;
	time_t now, gap;
	time(&now);
	gap = now - last_reload;
	if(gap >= rules_reload_time_interval){
		last_reload = now;
		return TRUE;
	}
	return FALSE;
}

void
pass_to_motor(gpointer args) {

	PyObject *pcheck, *pyobj_proxy, *py_arguments;
	pcheck = pyobj_proxy = py_arguments = NULL;

	do {
		data_2_python(args, &pyobj_proxy);
		if (pyobj_proxy == NULL){
			ERROR("Not able to generate the python diction proxy");
			break;
		}

		py_arguments = Py_BuildValue("(O,i)", pyobj_proxy, ((struct motor_args*)args)->type_id);
		if (py_arguments == NULL) {
			ERROR("Not able to build the args");
			break;
		}

		if(update_rules(((struct motor_args*)args)->motor_env, ((struct motor_args*)args)->ns_name) == -1){
			ERROR("No rules available, not passing to rules motor");
			break;
		}
		pcheck = PyEval_CallObject((*((struct motor_args*)args)->motor_env)->py_function, py_arguments);
		if (pcheck == NULL) {
			ERROR("Not able to evaluate the function");
			break;
		}
	} while (0);
	Py_XDECREF(pcheck);
	Py_XDECREF(pyobj_proxy);
	Py_XDECREF(py_arguments);
}

gpointer
pass_to_motor_v_multi_thread(gpointer args){

	PyEval_AcquireLock();
	PyInterpreterState * mainInterpreterState = mainThreadState->interp;
	PyThreadState * myThreadState = PyThreadState_New(mainInterpreterState);
	PyThreadState_Swap(myThreadState);

	pass_to_motor(args);

	PyThreadState_Swap(NULL);
	PyThreadState_Clear(myThreadState);
	PyThreadState_Delete(myThreadState);
	PyEval_ReleaseLock();

	return NULL;
}

void
chunk_textinfo_extra_free_content(struct chunk_textinfo_extra_s *ctie){
	if(!ctie)
		return;
	if(ctie->compressedsize)
		g_free(ctie->compressedsize);
	if(ctie->metadatacompress)
		g_free(ctie->metadatacompress);
	memset(ctie, 0x00, sizeof(struct chunk_textinfo_extra_s));
}



void sqlx_crawler_data_block_init(struct crawler_sqlx_data_pack_s *data_block,
	 const gchar *sqlx_path, const gchar *sqlx_seq, const gchar *sqlx_cid, 
	 const gchar *sqlx_type, char *sqlx_url)
{
	data_block->sqlx_path = g_strdup(sqlx_path);
	data_block->sqlx_seq  = g_strdup(sqlx_seq);
	data_block->sqlx_cid  = g_strdup(sqlx_cid);
	data_block->sqlx_type = g_strdup(sqlx_type);
	data_block->sqlx_url  = g_strdup(sqlx_url);
}

void sqlx_crawler_data_block_free(struct crawler_sqlx_data_pack_s *data_block)
{
	g_free(data_block->sqlx_path);
	g_free(data_block->sqlx_seq);
	g_free(data_block->sqlx_cid);
	g_free(data_block->sqlx_type);
	g_free(data_block->sqlx_url);
	g_free(data_block);
}



void meta2_crawler_data_block_init(struct crawler_meta2_data_pack_s *data_block, 
	const gchar *container_path, char *meta2_url)
{
	gchar *container_id;
	container_id = g_strrstr(container_path, "/") + 1;
	data_block->container_path = g_strdup(container_path);
	data_block->container_id = g_strdup(container_id);
	data_block->meta2_url = g_strdup(meta2_url);
}

void meta2_crawler_data_block_free(struct crawler_meta2_data_pack_s *data_block)
{
	g_free(data_block->container_path);
    g_free(data_block->container_id);
    g_free(data_block->meta2_url);
    g_free(data_block);
}





/* gether the informations got from chunk_crawler into one structure */
void
chunk_crawler_data_block_init(struct crawler_chunk_data_pack_s *data_block,
   struct content_textinfo_s *content, struct chunk_textinfo_s *chunk, struct chunk_textinfo_extra_s *chunk_info_extra,
   struct stat *chunk_stat, const char *chunk_path){
	memset(data_block, 0x00, sizeof(struct crawler_chunk_data_pack_s));
	data_block->content_info = content;
	data_block->chunk_info = chunk;
	data_block->chunk_info_extra = chunk_info_extra;
	if (chunk_stat != NULL) {
		data_block->atime = chunk_stat->st_atime;
		data_block->ctime = chunk_stat->st_ctime;
		data_block->mtime = chunk_stat->st_mtime;
	}
	data_block->chunk_path = chunk_path;
}



/* initiate motor args */
void
motor_args_init(struct motor_args *args, gpointer data_block, gint8 type_id,
		struct rules_motor_env_s** me, gchar *ns_name){
	args->data_block = data_block;
	args->type_id = type_id;
	args->motor_env = me;
	args->ns_name = ns_name;
}

/* Read extra content info from chunk attributes */
struct attr_handle_s{
	int xattr_supported;
	char *chunk_path;
	int chunk_file_des;
	char *attr_path;
	int attr_file_des;
	GHashTable *attr_hash;
};

static struct attr_handle_s *
_alloc_attr_handle(const gchar * chunk_path)
{
	struct attr_handle_s *attr_handle = NULL;

	attr_handle = g_try_malloc0(sizeof(struct attr_handle_s));
	if (!attr_handle)
		goto error_handle;

	attr_handle->chunk_path = g_strdup(chunk_path);
	if (!attr_handle->chunk_path)
		goto error_chunk_path;

	attr_handle->attr_path = g_strdup_printf("%s.attr", chunk_path);
	if (!attr_handle->attr_path)
		goto error_attr_path;

	attr_handle->attr_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	if (!attr_handle->attr_hash)
		goto error_hash;

	attr_handle->attr_file_des = -1;
	attr_handle->chunk_file_des = -1;
	return attr_handle;

error_hash:
	g_free(attr_handle->attr_path);
error_attr_path:
	g_free(attr_handle->chunk_path);
error_chunk_path:
	g_free(attr_handle);
error_handle:
	return NULL;
}

static gboolean
_load_from_file_attr(struct attr_handle_s *attr_handle, GError ** error){
	FILE *stream;
	struct stat chunk_stats;
	char lineBuf[65536];

	if (attr_handle->attr_hash == NULL) {
		SETERRCODE(error, EINVAL, "Invalid parameter : attr_hash is null");
		return FALSE;
	}

	/* stat the file */
	if (0 > stat(attr_handle->attr_path, &chunk_stats)) {
		SETERRCODE(error, errno, "Attr file [%s] not found for chunk", attr_handle->attr_path);
		return FALSE;
	}

	stream = fopen(attr_handle->attr_path, "r");
	if (!stream) {
		SETERRCODE(error, errno, "Failed to open stream to file [%s] : %s)",
			attr_handle->attr_path, strerror(errno));
		return FALSE;
	}

	while (fgets(lineBuf, sizeof(lineBuf), stream)) {
		/* Remove trailing \n */
		int line_len = strlen(lineBuf);
		if (lineBuf[line_len-1] == '\n')
			lineBuf[line_len-1] = '\0';

		char **tokens = g_strsplit(lineBuf, ":", 2);

		if (tokens) {
			if (*tokens && *(tokens + 1)) {
				g_hash_table_insert(attr_handle->attr_hash, *tokens, *(tokens + 1));
				g_free(tokens);
			}
			else
				g_strfreev(tokens);
		}
	}

	fclose(stream);

	return TRUE;
}

static gboolean
_getxattr_from_chunk(struct attr_handle_s *attr_handle, GError ** error, const char *attrname, char **result){
	ssize_t attr_value_size;

	if (!result || !attr_handle || !attrname) {
		SETERRCODE(error, EINVAL, "Invalid parameter");
		return -1;
	}

	attr_value_size = getxattr(attr_handle->chunk_path, attrname, NULL, 0);

	if (0 > attr_value_size) {
		SETERRCODE(error, errno, "Failed to get xattr [%s] from file [%s] : %s",
			attrname, attr_handle->chunk_path, strerror(errno));
		*result = NULL;
		return FALSE;
	}
	else if (0 == attr_value_size) {
		*result = g_try_malloc0(1);
		if (*result == NULL) {
			SETERRCODE(error, ENOMEM, "Memory allocation failure");
			return FALSE;
		}
	}
	else {
		*result = g_try_malloc0(attr_value_size + 1);
		if (*result == NULL) {
			SETERRCODE(error, ENOMEM, "Memory allocation failure");
			return FALSE;
		}
	}

	getxattr(attr_handle->chunk_path, attrname, *result, attr_value_size);

	return TRUE;
}

static gboolean
_load_from_xattr(struct attr_handle_s *attr_handle, GError ** error){
	char *last_name, *buf;
	register ssize_t i;
	ssize_t bufSize, bufMax;
	GError *local_error = NULL;

	if (attr_handle->attr_hash == NULL) {
		SETERRCODE(error, EINVAL, "Invalid parameter : attr_hash is null");
		return FALSE;
	}

	bufMax = listxattr(attr_handle->chunk_path, NULL, 0);
	if (0 > bufMax) {
		SETERRCODE(error, errno, "Failed to list XAttr : %s", strerror(errno));
		return FALSE;
	}
	if (0 == bufMax) {
		/* According to the man page, listxattr should return -1 if xattr
		 * is not supported by the underlying fs. It looks that in reality,
		 * it just returns a size of 0, so we'll consider this as an error. */
		SETERRCODE(error, ENOTSUP, "Failed to list xattr from chunk [%s] : size of list of attr names is 0",
				attr_handle->chunk_path);
		return FALSE;
	}

	buf = g_malloc0(bufMax);
	bufSize = listxattr(attr_handle->chunk_path, buf, bufMax);

	for (last_name = buf, i = 0; i < bufSize; i++) {
		if (buf[i] == '\0') {
			char *value = NULL;

			if (_getxattr_from_chunk(attr_handle, &local_error, last_name, &value))
				g_hash_table_insert(attr_handle->attr_hash, g_strdup(last_name), value);
			else {
				SETERRCODE(error, local_error->code, "Cannot get xattr %s from %s : %s",
						last_name, attr_handle->chunk_path, local_error->message);
				g_clear_error(&local_error);

				g_free(buf);
				return FALSE;
			}
			last_name = buf + i + 1;
		}
	}

	g_free(buf);
	return TRUE;
}

static gboolean
_load_attr_from_file(const char *chunk_path, struct attr_handle_s** attr_handle, GError ** error){
	GError *local_error = NULL;
	if (!(*attr_handle = _alloc_attr_handle(chunk_path))) {
		SETERRCODE(error, ENOMEM, "Memory allocation failure");
		return FALSE;
	}
	/* Try to load attributes from the local file and overwrite with xattr */
	_load_from_file_attr(*attr_handle, &local_error);
	if (local_error)
		g_clear_error(&local_error);

	_load_from_xattr(*attr_handle, &local_error);
	if (local_error)
		g_clear_error(&local_error);

	*error = NULL;
	return TRUE;
}

static gboolean
_get_attr_from_handle(struct attr_handle_s *attr_handle, GError ** error, const char *domain, const char *attrname, char **result){
	char attr_name_buf[ATTR_NAME_MAX_LENGTH], *value;

	if (!attr_handle || !domain || !attrname || !result) {
		SETERRCODE(error, EINVAL, "Invalid argument (%p %p %p %p)",
				attr_handle, domain, attrname, result);
		return FALSE;
	}       

	memset(attr_name_buf, '\0', sizeof(attr_name_buf));
	snprintf(attr_name_buf, sizeof(attr_name_buf), "%s.%s", domain, attrname);

	value = g_hash_table_lookup(attr_handle->attr_hash, attr_name_buf);
	if (value) { 
		*result = g_strdup(value);
		return TRUE;
	}       
	TRACE("Attribute [%s] not found for chunk [%s]", attr_name_buf, attr_handle->chunk_path);
	*result = NULL;
	return TRUE;
}       

// FIXME TODO XXX Duplicated from rawx-lib
static void
_clean_attr_handle(struct attr_handle_s *attr_handle, int content_only)
{
	if (!attr_handle)
		return;

	if (attr_handle->chunk_path) {
		g_free(attr_handle->chunk_path);
		attr_handle->chunk_path = NULL;
	}
	if (attr_handle->attr_path) {
		g_free(attr_handle->attr_path);
		attr_handle->attr_path = NULL;
	}
	if (attr_handle->attr_hash) {
		g_hash_table_destroy(attr_handle->attr_hash);
		attr_handle->attr_hash = NULL;
	}
	if (attr_handle->chunk_file_des >= 0)
		metautils_pclose(&(attr_handle->chunk_file_des));
	if (attr_handle->attr_file_des >= 0)
		metautils_pclose(&(attr_handle->attr_file_des));

	if (!content_only)
		g_free(attr_handle);
}

gboolean
get_extra_chunk_info(const char *pathname, GError ** error, struct chunk_textinfo_extra_s *chunk_textinfo_extra){
	struct attr_handle_s *attr_handle;
	GError *local_error = NULL;

	if(!_load_attr_from_file(pathname, &attr_handle, &local_error)){
		SETERROR(error, "Failed to init the attribute management context : %s", local_error->message);
		g_clear_error(&local_error);
		return FALSE;
	}
	
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,\
		ATTR_NAME_CHUNK_COMPRESSED_SIZE, &(chunk_textinfo_extra->compressedsize)))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,\
		ATTR_NAME_CHUNK_METADATA_COMPRESS, &(chunk_textinfo_extra->metadatacompress)))
		goto error_get_attr;
	
	_clean_attr_handle(attr_handle, FALSE);
	return TRUE;

error_get_attr:
	SETERROR(error, "Failed to get attr : %s", local_error->message);
	g_clear_error(&local_error);
	_clean_attr_handle(attr_handle, FALSE);
	return FALSE;
}


/* specific data convert for chunk_crawler */
void
data_2_python(gpointer args, PyObject** pyobj_proxy){

	PyObject *pdatablock;

	switch(((struct motor_args*)args)->type_id){
		case 0:{
			break;
		}
		case 1:{
			break;
		}
		case 2:{
			/* type_id 2 represents meta2 */
			struct crawler_meta2_data_pack_s *data_block;
			data_block = ((struct motor_args*)args)->data_block;
			pdatablock = Py_BuildValue("{s:s, s:s, s:s, s:s}",
						"container_path", data_block->container_path,
						"container_id", data_block->container_id,
						"meta2_url", data_block->meta2_url,
						"ns_name", ((struct motor_args*)args)->ns_name);
			*pyobj_proxy = PyDictProxy_New(pdatablock);
			Py_XDECREF(pdatablock);
			break;
		}
		case 3:
		case 4:{ 
			/* type_id 3 represents crawler */
			PyObject *content_info = NULL, *chunk_info = NULL;
			struct crawler_chunk_data_pack_s *data_block;
			data_block = ((struct motor_args*)args)->data_block;

			/* data from content_info */
			if (data_block->content_info)
			content_info = Py_BuildValue("{s:s, s:s, s:s, s:s, s:s, s:s}", 
						"container_id", data_block->content_info->container_id,	/* the container id */
						"path", data_block->content_info->path,	/* the content name */
						"content_size", data_block->content_info->size,	/* the content size */
						"chunk_nb", data_block->content_info->chunk_nb,	/* the number of chunks */
						"metadata", data_block->content_info->metadata,	/* the user metadata */
						"system_metadata", data_block->content_info->system_metadata	/* the system metadata */
						);
			else
				content_info = Py_BuildValue("");
			/* data from chunk_info */
			if (data_block->chunk_info)
			chunk_info = Py_BuildValue("{s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:s, s:s}", 
						"id", data_block->chunk_info->id,	/* the chunk id */
						"path", data_block->chunk_info->path,	/* the chunk path */
						"size", data_block->chunk_info->size,	/* the chunk size */
						"position", data_block->chunk_info->position,	/* the chunk position */
						"hash", data_block->chunk_info->hash,	/* the chunk hash */
						"metadata", data_block->chunk_info->metadata,	/* the chunk metadata */
						"container_id", data_block->chunk_info->container_id,	/* the container id */
						/*"last_scanned_time", data_block->chunk_info_extra->last_scanned_time,	 last_scanned_time */
						"compressedsize", data_block->chunk_info_extra->compressedsize,		/* size of compressed chunk */
						"metadatacompress", data_block->chunk_info_extra->metadatacompress	/* metadata of compressed chunk */
						);
			else
				chunk_info = Py_BuildValue("");
			/* build the pdatablock */
			pdatablock = Py_BuildValue("{s:O, s:O, s:l, s:l, s:l, s:s, s:s}",
						"content_info", content_info,
						"chunk_info", chunk_info,
						"atime", data_block->atime,
						"ctime", data_block->ctime,
						"mtime", data_block->mtime,
						"chunk_path", data_block->chunk_path,
						"ns_name", ((struct motor_args*)args)->ns_name
						);
			*pyobj_proxy = PyDictProxy_New(pdatablock);
			Py_XDECREF(pdatablock);
			Py_XDECREF(content_info);
			Py_XDECREF(chunk_info);
			break;
		}
		case 5:{
            /* type_id 5 represents sqlx */
            struct crawler_sqlx_data_pack_s *data_block;
            data_block = ((struct motor_args*)args)->data_block;
            pdatablock = Py_BuildValue("{s:s, s:s, s:s, s:s, s:s, s:s}",
			            "sqlx_path", data_block->sqlx_path,
						"sqlx_seq", data_block->sqlx_seq,
						"sqlx_cid", data_block->sqlx_cid,
						"sqlx_type", data_block->sqlx_type,
						"sqlx_url", data_block->sqlx_url,
						"ns_name", ((struct motor_args*)args)->ns_name);
			*pyobj_proxy = PyDictProxy_New(pdatablock);
			Py_XDECREF(pdatablock);
			break;
		}
		default:{
			ERROR("type_id: %d not defined in c2python.c", ((struct motor_args*)args)->type_id);
			break;
		}
	}
}

/* destroy the meta2-crawler datablock */
void
destroy_crawler_meta2_data_block(struct crawler_meta2_data_pack_s *data_block){
	g_free(data_block->container_path);
	g_free(data_block->container_id);
	g_free(data_block->meta2_url);
	free(data_block);
}

/* destroy the motor environment */
void
destroy_motor_env(struct rules_motor_env_s** me){
	Py_XDECREF((*me)->py_function);
	Py_XDECREF((*me)->py_module);
	Py_Finalize();
	g_free(*me);
}

/* destroy the motor environment */
void
destroy_motor_env_v_multi_thread(struct rules_motor_env_s** me){
	Py_XDECREF((*me)->py_function);
	Py_XDECREF((*me)->py_module);
	PyEval_RestoreThread(mainThreadState);
	Py_Finalize();
	free(*me);
}

