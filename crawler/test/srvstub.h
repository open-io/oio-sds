#ifndef __SRVSTUB_H
#define __SRVSTUB_H



typedef enum {
	SSCMD_ALL_OK = 0,
	SSCMD_ALL_NONE,
	SSCMD_ALL_OK_WITHOUTDATA,
	SSCMD_ALL_ERR_WITHOUTDATA,
    SSCMD_ONE_ERR_WITHOUTDATA,

	SSCMD_max
} ESrvStubCmd;

typedef struct SSrvStubHandle TSrvStubHandle;

TSrvStubHandle* srvstub_init( char* url, ESrvStubCmd sscmd, char* name, void* responsedata);
GError*         srvstub_run(  TSrvStubHandle* s);
int             srvstub_close(TSrvStubHandle** s);




#endif

