#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <time.h>

// TODO FIXME replace with GLib equivalent
#include <openssl/md5.h>

#include <../lib/gs_internals.h>

int main (int argc, char ** args)
{
	int rc = -1;

	gs_error_t *err = NULL;
	gs_grid_storage_t *hc;
	gs_container_t *container;
	char *ns;
	char cname[60];

	srand(time(NULL));

	if (argc != 2) {
		g_error("Usage: %s NS\n", args[0]);
		return rc;
	}

	ns = args[1];

	bzero(cname, sizeof(cname));
	g_snprintf(cname, sizeof(cname), "SOLR%d", rand());

	printf("Working with container [%s]\n", cname);

	hc = gs_grid_storage_init( ns, &err );
	if(!hc) {
		printf("failed to init hc\n");
		return rc;
	}

	container = gs_get_container(hc, cname, 1, &err);
	if(!container) {
		printf("Failed to resolve container\n");
		goto end_label;
	}

	gs_service_t **srv_array = NULL;
	srv_array = gs_container_service_get_available(container, "meta0", &err);
	char url[256];
	bzero(url, sizeof(url));
	gs_service_get_url(srv_array[0], url, sizeof(url));
	printf("New service linked\n");
	printf("service url = [%s]\n", url);

	if(srv_array)
		gs_service_free_array(srv_array); 
	
	srv_array = gs_container_service_get_all(container, "meta0", &err);

	bzero(url, sizeof(url));
	gs_service_get_url(srv_array[0], url, sizeof(url));
	printf("Already linked service :\n");
	printf("service url = [%s]\n", url);

	if(srv_array)
		gs_service_free_array(srv_array); 

end_label:

	if(container) {
		gs_container_free(container);
		container = NULL;
	}

	if(hc) {
		gs_grid_storage_free(hc);
		hc = NULL;
	}

	if(err) {
		gs_error_free(err);
		err= NULL;
	}
}

