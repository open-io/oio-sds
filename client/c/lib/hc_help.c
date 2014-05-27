#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "hc.tools"
#endif

#include "./gs_internals.h"
#include "./hc.h"

void help_put(void)
{
	g_printerr("\n");
	g_printerr("usage: hc put <NS>/<CONTAINER_NAME>[/<CONTENT_NAME>] [<PATH_TO_FILE>]\n\n");
	g_printerr("\tCreates a new container or upload a new content in a container.\n\n");
	g_printerr("\t            NS : The Honeycomb namespace name\n");
	g_printerr("\tCONTAINER_NAME : The container to create or to upload content in.\n");
	g_printerr("\t  CONTENT_NAME : The name to give to the uploaded content.\n");
	g_printerr("\t  PATH_TO_FILE : The path of the local file to upload.\n");
	g_printerr("\n");
}

void help_get(void)
{
	g_printerr("\n");
	g_printerr("usage: hc get <NS>/<CONTAINER_NAME>[/<CONTENT_NAME>][?version=<CONTENT_VERSION>] [<PATH_TO_FILE>]\n\n");
	g_printerr("\tList contents of a container or download a content from a container.\n\n");
	g_printerr("\t             NS : The Honeycomb namespace name\n");
	g_printerr("\t CONTAINER_NAME : The container to list contents from or which contains the content to download.\n");
	g_printerr("\t   CONTENT_NAME : The name of the content to download.\n");
	g_printerr("\tCONTENT_VERSION : The version of the content (or snapshot name) to download. (latest version is downloaded if not specified)\n");
	g_printerr("\t   PATH_TO_FILE : The path of the local file in which to store the downloaded content.\n");
	g_printerr("\n");
}

void help_delete(void)
{
	g_printerr("\n");
	g_printerr("usage: hc delete <NS>/<CONTAINER_NAME>[/<CONTENT_NAME>][?version=<CONTENT_VERSION>]\n\n");
	g_printerr("\tDestroy a container or a content.\n\n");
	g_printerr("\t             NS : The Honeycomb namespace\n");
	g_printerr("\t CONTAINER_NAME : The container to destroy or which contains the content to delete.\n");
	g_printerr("\t   CONTENT_NAME : The path of the content to delete.\n");
	g_printerr("\tCONTENT_VERSION : The version of the content to delete.\n");
	g_printerr("\n");
}

void help_append(void)
{
	g_printerr("\n");
	g_printerr("usage: hc append <NS>/<CONTAINER_NAME>/<CONTENT_NAME> <PATH_TO_FILE>\n\n");
	g_printerr("\tAppend data to an existing content.\n\n");
	g_printerr("\t            NS : The Honeycomb namespace\n");
	g_printerr("\tCONTAINER_NAME : The container which contains the content.\n");
	g_printerr("\t  CONTENT_NAME : The name of the content.\n");
	g_printerr("\t  PATH_TO_FILE : The path of the local file to append to the content.\n");
	g_printerr("\n");
}

void help_info(void)
{
	g_printerr("\n");
	g_printerr("usage: hc info <NS>/<CONTAINER_NAME>[/<CONTENT_NAME>][?version=<CONTENT_VERSION>]\n\n");
	g_printerr("\tShow informations about a container or a content\n\n");
	g_printerr("\t             NS : The Honeycomb namespace\n");
	g_printerr("\t CONTAINER_NAME : The container to get informations from.\n");
	g_printerr("\t   CONTENT_NAME : The content to get informations from.\n");
	g_printerr("\tCONTENT_VERSION : The content version (or snapshot name) to get informations from.\n");
	g_printerr("\n");
}

void help_stgpol(void)
{
	g_printerr("usage: hc stgpol <NS>/<CONTAINER_NAME>/<PATH> [STGPOL]\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    CONTAINER_NAME: The container you want to set the storage policy or which contain your content.\n");
	g_printerr("    PATH: The targeted content path. If not specified, this command work on container storage policy\n");
	g_printerr("    STGPOL: The storage policy to set. If not specify, this command dump the current policy of the container\n\n");
}

void help_quota(void)
{
	g_printerr("usage: hc quota <NS>/<CONTAINER_NAME> QUOTA\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    CONTAINER_NAME: The container you want to set the storage policy or which contain your content.\n");
	g_printerr("    QUOTA: The quota to set\n\n");
}
void help_version(void)
{
	g_printerr("usage: hc version <NS>/<CONTAINER_NAME> VERSIONING\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    CONTAINER_NAME: The container you want to set the storage policy or which contain your content.\n");
	g_printerr("    VERSIONING: The versioning to set. There is 4 "
				"possibility to the versioning status:\n");
	g_printerr("		-2 : Use the default versioning value of the namespace\n");
	g_printerr("		-1 : The number of versions of a content is unlimited and never purged\n");
	g_printerr("		 0 : Deactivate the versioning on the container. The behaviour of meta2 services is like in Honeycomb 1.7 and older\n");
	g_printerr("		 1 : Override mode. Uploading a content on an existing content replace the content"
				" in place by the new (comparable to Amazon S3 basic mode\n");
	g_printerr("		 n (n > 1) : N is the number of version kept for each content. Each exceeding version is dropped asynchronously.\n");
}

void help_srvlist(void)
{
	g_printerr("usage: hcdir srvlist <NS>/<CONTAINER_NAME> <SRV_TYPE>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    CONTAINER_NAME: The container you want to list services.\n");
	g_printerr("    SRV_TYPE: The type of service you want to list (set ALL if you want to get all service types linked).\n");
}

void help_srvlink(void)
{
	g_printerr("usage: hc srvlink <NS>/<CONTAINER> <SRV_TYPE>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    CONTAINER: The container you want to link service to.\n");
	g_printerr("    SRV_TYPE: The type of service you want to link.\n");
}

void help_srvunlink(void)
{
	g_printerr("usage: hc srvunlink <NS>/<CONTAINER> <SRV_TYPE>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    CONTAINER: The container you want to unlink service from.\n");
	g_printerr("    SRV_TYPE: The type of service you want to unlink.\n");
	g_printerr("    (This functionally will be improved later.)\n");
}

void help_srvpoll(void) {
	g_printerr("usage: hc srvpoll <NS>/<CONTAINER> <TYPE>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    CONTAINER: The container you want to manage services.\n");
	g_printerr("    TYPE: A type of service managed in the given namespace.\n");
}

void help_srvforce(void) {
	g_printerr("usage: hc srvforce <NS>/<CONTAINER> '<SEQ>|<TYPE>|<URL>|<ARGS>'\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    CONTAINER: The container you want to work with.\n");
	g_printerr("    SEQ: The sequence number for the given (service,container) association\n");
	g_printerr("    TYPE: A type of service managed in the given namespace\n");
	g_printerr("    URL: the network address of the given service\n");
	g_printerr("    ARGS: some service-dependent arguments attached to this (service,container) association\n");
}

void help_srvconfig(void) {
	g_printerr("usage: hc srvconfig <NS>/<REF> '<SEQ>|<TYPE>|<URL>|<ARGS>'\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    REF: The container you want to work with.\n");
	g_printerr("    SEQ: The sequence number for the given (service,container) association\n");
	g_printerr("    TYPE: A type of service managed in the given namespace\n");
	g_printerr("    URL: the network address of the given service\n");
	g_printerr("    ARGS: the new service-dependent arguments that will ve attached to this (service,container) association\n");
}

void help_propset(void) {
	g_printerr("usage: hc propset <NS>/<CONTAINER>/<CONTENT> <KEY> <VALUE>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    CONTAINER: The container you want to work with.\n");
	g_printerr("    CONTENT: The content you want to work with.\n");
	g_printerr("    KEY: the name of the property to set\n");
	g_printerr("    VALUE: the value of the property to set\n");
}

void help_propget(void) {
	g_printerr("usage: hc propget <NS>/<CONTAINER>/<CONTENT>\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    CONTAINER: The container you want to work with.\n");
	g_printerr("    CONTENT: The content you want to work with.\n");
}


void help_propdel(void) {
	g_printerr("usage: hc propdel <NS>/<CONTAINER>/<CONTENT> <KEY> ....\n\n");
	g_printerr("    NS: Honeycomb namespace, if you don't know this, please contact your Honeycomb namespace administrator\n");
	g_printerr("    CONTAINER: The container you want to work with.\n");
	g_printerr("    CONTENT: The content you want to work with.\n");
	g_printerr("    KEY: the property key.\n");
}

void help_snaplist(void)
{
	g_printerr("\n");
	g_printerr("usage: hc snaplist <NS>/<CONTAINER_NAME>\n\n");
	g_printerr("\tList snapshots of a container\n\n");
	g_printerr("\t             NS: The Honeycomb namespace name\n");
	g_printerr("\t CONTAINER_NAME: The container to list snapshots from\n");
	g_printerr("\n");
}

void help_snaptake(void)
{
	g_printerr("\n");
	g_printerr("usage: hc snaptake <NS>/<CONTAINER_NAME>?snapshot=<SNAPSHOT_NAME>\n\n");
	g_printerr("\tTake a snapshot of a container\n\n");
	g_printerr("\t             NS: The Honeycomb namespace name\n");
	g_printerr("\t CONTAINER_NAME: The container to take a snapshot of\n");
	g_printerr("\t  SNAPSHOT_NAME: A name for the snapshot (must not start with a digit)\n");
	g_printerr("\n");
}
void help_snapdel(void)
{
	g_printerr("\n");
	g_printerr("usage: hc snapdel <NS>/<CONTAINER_NAME>?snapshot=<SNAPSHOT_NAME>\n\n");
	g_printerr("\tDelete a snapshot\n\n");
	g_printerr("\t             NS: The Honeycomb namespace name\n");
	g_printerr("\t CONTAINER_NAME: The container to delete snapshot from\n");
	g_printerr("\t  SNAPSHOT_NAME: The name of the snapshot to delete\n");
	g_printerr("\n");
}
void help_snaprestore(void)
{
	g_printerr("\n");
	g_printerr("usage: hc snaprestore <NS>/<CONTAINER_NAME>?snapshot=<SNAPSHOT_NAME>\n");
	g_printerr("or     hc snaprestore <NS>/<CONTAINER_NAME>/<CONTENT_NAME>?snapshot=<SNAPSHOT_NAME>\n\n");
	g_printerr("\tRestore a snapshot or a content from a snapshot\n\n");
	g_printerr("\t             NS: The Honeycomb namespace name\n");
	g_printerr("\t CONTAINER_NAME: The container to restore snapshot of\n");
	g_printerr("\t   CONTENT_NAME: The content to restore from the snapshot\n");
	g_printerr("\t  SNAPSHOT_NAME: The name of the snapshot to restore\n");
	g_printerr("\n");
}

