#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "crawler.test"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>

#include <metautils/lib/metautils.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <glib/gprintf.h>

#include "../lib/crawler_common.h"
#include "srvstub.h"
#include "binredir.h"

//--------------------------------------------------------
//
#define TEST_ERRMSG_TRIP_FAILEDSTART "Trip library Failed to Start"  
#define TEST_ERRMSG_TRIP_MISSINGARG  "Trip library Failed to Start: Missing error about bad param"

#define TEST_ERRMSG_CRAWLER_FAILEDSTART  "Crawler Failed to start"
#define TEST_ERRMSG_CRAWLER_BADARGS      "Crawler Failed to start: bad args"
#define TEST_ERRMSG_CRAWLER_BADTRIP      "Crawler Failed to start: Missing/bad litrip"
#define TEST_ERRMSG_CRAWLER_BADACTION    "Crawler Failed to Start: Missing/bad action"

#define TEST_ERRMSG_ACTION_MISSINGERR   "Action Failed during run: No error occur"
#define TEST_ERRMSG_ACTION_FAILEDSRV    "Action Failed during run: An error occur"
#define TEST_ERRMSG_ACTION_FAILEDSTART  "Action Failed to start"

//
#define ARG_MAX    1024

static gchar* url_srvstub        = "127.0.0.1:6099";
static gchar* path_triplib       = "/usr/local/lib64/grid";
static int    g_binredir_timeout = 30;                      //timeout "bin redirection no response"
static TBinRedir*      g_hbin     = NULL;
static TBinRedir*      g_hbin_crawler = NULL;
static TSrvStubHandle* g_hsrvstub = NULL;
static gboolean        g_bverbose = FALSE;
static gboolean        g_bdebug   = FALSE;
static char            g_args[ARG_MAX]     = "";
static char            g_bin_name[ARG_MAX] = "";

//--------------------------------------------------------

#define TEST_START() \
	g_hbin         = NULL;\
g_hbin_crawler = NULL;\
g_hsrvstub     = NULL

#define TEST_END() {\
	if (g_hbin) binredir_stop(&g_hbin);\
	if (g_hbin_crawler) binredir_stop(&g_hbin_crawler); \
	if (g_hsrvstub) srvstub_close(&g_hsrvstub);\
	sleep(1); \
	g_free(g_hsrvstub); }

#define TEST_END_WITH_ERROR(...) {\
	TEST_END(); \
	g_error(__VA_ARGS__); }

#define TEST_VERBOSE(...) if (g_bverbose) fprintf(stdout, __VA_ARGS__)

#define TEST_DEBUG(...)   if (g_bdebug)   fprintf(stdout, __VA_ARGS__)



//--------------------------------------------------------
void libtrip_close(struct trip_lib_entry_points** ep)
{
	if (!ep || !*ep) 
		return;

	(*ep)->trip_end();
	free_trip_lib_entry_points(*ep);
	*ep = NULL;
}


struct trip_lib_entry_points* libtrip_load(char* path, char* trip)
{
	return (struct trip_lib_entry_points*) load_trip_library(path, trip);
}




int  __binary_getError(TBinRedir* handle, char* errmsg, int size)
{
#define BUFF_MAX  1024
	char buff[BUFF_MAX] = "";
	int nb = 0;
	int len;

	errmsg[0] = '\0';

	// parent process

	nb = binredir_get(handle, (char*)buff, BUFF_MAX, g_binredir_timeout);

	// timeout? error?
	if (nb < 0)  
		return -1;

	// no byte read
	if (nb == 0)			
		return 0;	

	// bytes read
	GString* str = g_string_new(buff); 
	str          = g_string_ascii_up(str);
	char* tmp    = g_string_free(str, FALSE);

	// an error/warning ?
	gboolean bErr = FALSE;
	gboolean bWarn = FALSE;
	if (   (strstr(tmp,    "FAILED"))
			||(strstr(tmp, "ERROR" ))
			||(strstr(tmp, " ERR " ))) {
		bErr = TRUE;
	} else if (strstr(tmp, " WRN ")){
		bWarn = TRUE;
	}
	g_free(tmp);

	// save it ?!
	if ((bErr == TRUE) || (bWarn == TRUE)) {
	    len = size;
	    if (len > (int)strlen(buff))
	        len = strlen(buff);
		g_strlcpy(errmsg, buff, len);
		TEST_VERBOSE("%s> [%s]\n", (bErr?"ERR":"WRN"), buff);
		return 1;
	} else TEST_DEBUG("OUT> [%s]\n", buff);

	
	return 0;
}




/** return TRUE if ENDTEST WITH ERROR, else FALSE
 * */
static gboolean _binredir_manage_error(TBinRedir* hbin, gboolean bTestTrueIsGood, gchar* msgIfFailed, gboolean* bEnd, gboolean* bErr)
{
	int nb = 0;
	char errmsg[1024] = "";

	nb = __binary_getError(hbin, errmsg, 1023);
	if ( nb < 0) {
		*bEnd = TRUE;
	} else if ( nb > 0) {
		if (strlen(errmsg) > 0) {
			*bErr = TRUE;
			if (bTestTrueIsGood == TRUE) {
				TEST_END_WITH_ERROR("An error occurs by crawler, %s: %s\n", msgIfFailed, errmsg);
			} else *bEnd = TRUE;
		}
	}
}


//------------------------------------------------------------------------------


static struct trip_lib_entry_points* __test_trip_loadandstart(char* path, char* trip, char* args, gboolean bTestTrueIsGood, gchar* errMsg)
{

	struct trip_lib_entry_points* ep = libtrip_load(path, trip);
	if (ep) {
		char** argv = g_strsplit(args, " ", 0);
		int argc =  g_strv_length(argv);

		gboolean ret = TRUE;
		if (EXIT_FAILURE == (int)(ep->trip_start)(argc, argv))
			ret = FALSE;

		gboolean bOk = FALSE;
		if (bTestTrueIsGood == TRUE) {  // wait no error...
			if (ret == FALSE){               //  ... error occur
				TEST_END_WITH_ERROR("%s\n", errMsg);		
			} else bOk = TRUE;                //  ... no error
		} else if (ret == TRUE) {         // wait error...
			g_message(errMsg);             //  ... no error  
		}

		// if wait no error...and no error ! ===> continue
		if (bOk == FALSE)
			libtrip_close(&ep);
	}
	else TEST_END_WITH_ERROR("Trip library Failed to load\n");

	return ep;
}



static void __crawl(struct trip_lib_entry_points* ep)
{
	GVariant* occur = NULL;
	gboolean stop_thread = FALSE;

	occur = (GVariant*)(ep->trip_next)();
	while (!stop_thread && NULL != occur) {

		//send to stdout
		gchar* toccur = g_variant_print(occur, FALSE);

		g_printf("data: [%s]\n", toccur);
		g_free(toccur);

		// free data from trip
		if (NULL != occur)
			g_variant_unref(occur);

		//search the next data
		occur = (GVariant*)(ep->trip_next)();
	};
}



static gpointer _thread_srvstub_run(gpointer d)
{
	TSrvStubHandle* handle = (TSrvStubHandle*) d;
	GError* err = NULL;

	fprintf(stdout, "%s: START\n", __FUNCTION__);
	err = srvstub_run(handle);
	if (err ) {
		srvstub_close(&handle);
		g_free(handle);

		TEST_END_WITH_ERROR("Failed to run service stub (%s): (%d) %s\n", 
				url_srvstub, err->code, err->message);
		g_clear_error(&err);
	}
	fprintf(stdout, "%s: END\n", __FUNCTION__);

	return 0;
}




static void __spy_crawler_action(char* cmdline_action, char* cmdline_crawler, gboolean bTestTrueIsGood, char* msgIfFailed)
{
	// launch binary to test num1
	if ((cmdline_action != NULL) && (strlen(cmdline_action) > 0)) {
		TEST_VERBOSE("Launch...%s\n", cmdline_action);
		g_hbin = binredir_launch(cmdline_action);
		if (!g_hbin) {
			TEST_END_WITH_ERROR("Failed to initialize binaries (%s)\n", cmdline_action);
		} else
			sleep(1);
	}


	// launch binary to test num2
	if ((cmdline_crawler != NULL) && (strlen(cmdline_crawler) > 0)) {
		TEST_VERBOSE("Launch...%s\n", cmdline_crawler);
		g_hbin_crawler = binredir_launch(cmdline_crawler);
		if (!g_hbin_crawler)
			TEST_END_WITH_ERROR("Failed to initialize binaries (%s)\n", cmdline_crawler);
	}

	// check if errors occured
	gboolean bEnd=FALSE;
	gboolean bErr = FALSE;
	while (bEnd == FALSE) {
		// check error from crawler
		if (g_hbin_crawler) {
			_binredir_manage_error(g_hbin_crawler, bTestTrueIsGood, msgIfFailed, &bEnd, &bErr);
		}

		// check error from action
		if (g_hbin) {
			_binredir_manage_error(g_hbin, bTestTrueIsGood, msgIfFailed, &bEnd, &bErr);
		}
	};

	// to see error of crawler eventualy
	if (g_hbin_crawler)
		_binredir_manage_error(g_hbin_crawler, bTestTrueIsGood, msgIfFailed, &bEnd, &bErr);
	if (g_hbin) 
		_binredir_manage_error(g_hbin,         bTestTrueIsGood, msgIfFailed, &bEnd, &bErr);

	//------
	if (bTestTrueIsGood == FALSE) {
		if (bErr == FALSE) {
			TEST_END_WITH_ERROR("Missing on error for this test case ?!\n" );
		}
	}
}





//------------------------------------------------------------------------------


typedef struct STestCaseSrvStub {
	char*       url;          // url of stub services
	ESrvStubCmd sscmd;        // response mode
	char*       name;         // name of request
	GSList*       responsedata; // ...> name
}TTestCaseSrvStub;



//                                      test trip...                      |  test action
typedef struct STestCase{
	gchar*            bin_name;        // trip_name                       | action_name

	// common trip / action
	gchar*            args;            //        ligne de commande du crawler apres le "--" 

	// spesific trip_xx
	gboolean          startNotFailed;  // =TRUE if started w<ith no error | -

	//spesific action_xx
	TTestCaseSrvStub* testCaseData;    // -                               | trip test associate

	//spesific test
	gchar*            testcase_name;   //                           testcase name 
	void             (*test)(gconstpointer);
	gchar*            msgIfFailed;     //                           msg if failed
}TTestCase;






static void _test_trip_start(gconstpointer userdata)
{
	struct trip_lib_entry_points* ep = NULL;

	TEST_START();

	TTestCase* t = (TTestCase*) userdata;
	if (!t)
		g_error("Failed to launch any test!");

	ep = __test_trip_loadandstart(path_triplib, t->bin_name,  t->args, t->startNotFailed, t->msgIfFailed);
	if (ep) {
		// on crawl le repository
		__crawl(ep);
		libtrip_close(&ep);
	}

	TEST_END();
}



static void _test_crawler_simple(gconstpointer userdata)
{
	TEST_START();

	TTestCase* t = (TTestCase*) userdata;
	if (!t)
		g_error("Failed to launch any test!");

	printf("--------------------------------------------------\n");
	char cmdline_crawler[1024];
	g_snprintf(cmdline_crawler, 1023, "%s %s %s", t->bin_name, (g_bdebug?"-vvvvvvvv":""), t->args);

	__spy_crawler_action(NULL, cmdline_crawler, t->startNotFailed, t->msgIfFailed);

	TEST_END();
}



static void _test_action_simple(gconstpointer userdata)
{
	TEST_START();

	TTestCase* t = (TTestCase*) userdata;
	if (!t)
		g_error("Failed to launch any test!");

	TTestCaseSrvStub* tcss = (TTestCaseSrvStub*) t->testCaseData;

	printf("--------------------------------------------------\n");

	// build command line to test
	char cmdline_bin[1024]="";
	char cmdline_crawler[1024]="";
	g_snprintf(cmdline_bin,     1023, "%s %s",         t->bin_name, (g_bdebug?"-vvvvvvvv":""));
	g_snprintf(cmdline_crawler, 1023, "crawler -vvvvvvv %s",  t->args);

	sleep(1);

	// launch service stub
	if (tcss) {
		fprintf(stdout, "tcss->url=[%s], tcss->sscmd=[%d]\n", tcss->url, tcss->sscmd);
		g_hsrvstub = srvstub_init(tcss->url, tcss->sscmd, tcss->name, tcss->responsedata);
		if (!g_hsrvstub) 
			TEST_END_WITH_ERROR("Failed to initialize service stub (%s)\n", tcss->url);

		// launch service stub run
		GThread* th = g_thread_create(_thread_srvstub_run, g_hsrvstub, TRUE, NULL);

		sleep(2);
	}

	// surveillance crawler/action
	__spy_crawler_action(cmdline_bin, cmdline_crawler, t->startNotFailed, t->msgIfFailed);

	TEST_END();
}


static void _test_action_timeout(gconstpointer userdata)
{
	// enabled timeout
	binredir_exec("iptables -A INPUT -p tcp --dport 6099 -j DROP");

	_test_action_simple(userdata);
	
	// disabled timeout
	binredir_exec("iptables -D INPUT -p tcp --dport 6099 -j DROP");
}



//------------------------------------------------------------------------------


void usage(char* appname)
{
	g_printf("USAGE\n, %s [-d|--debug] [-v|--verbose] -b <trip_name_to_test> [-a <good_repository_about_s_arg - ONLY ERROR CASE if omited>] \n", appname);
}


gboolean getoption(int argc, char** argv)
{
	gboolean ret = TRUE;
	int c;

	g_bdebug   = FALSE;
	g_bverbose = FALSE;
	g_args[0] = '\0';
	g_bin_name[0] = '\0';

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"bin",      required_argument, 0,  'b' },
			{"args",     required_argument, 0,  'a' },
			{"debug",    no_argument,       0,  'd' },
			{"verbose",  no_argument,       0,  'v' },
			{0,          0,                 0,  0  }
		};

		c = getopt_long(argc, argv, "b:a:s:n:dv",
				long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
			case 'd': g_bdebug   = TRUE;   break;
			case 'v': g_bverbose = TRUE;   break; 
			case 'a': g_strlcpy(g_args,     optarg, ARG_MAX); break;
			case 'b': g_strlcpy(g_bin_name, optarg, ARG_MAX); break;
			case '?': ret = FALSE;         break;
			default: ret = FALSE;
		};
	}

	if (strlen(g_bin_name) == 0)
		ret = FALSE;

	return ret;
}


int main(int argc, char **argv)
{
	gchar* testcase = NULL;

	//init
	if (!g_thread_supported())
		g_thread_init(NULL);
	g_set_prgname(argv[0]);
	g_log_set_default_handler(logger_stderr, NULL);
	logger_init_level(GRID_LOGLVL_TRACE2);
	g_test_init (&argc, &argv, NULL);

	g_bverbose = FALSE;
	g_bdebug   = FALSE;

	if (getoption(argc, argv) == FALSE) {
		usage(argv[0]);
		exit(1);
	}

	//test case: trip
	static TTestCase testcase_trip[] = {
		{ g_bin_name, "/tmp",  FALSE, NULL, "xattr_not_found",      _test_trip_start, TEST_ERRMSG_TRIP_MISSINGARG},
		{ g_bin_name, "/toto", FALSE, NULL, "sourcepath_not_found", _test_trip_start, TEST_ERRMSG_TRIP_MISSINGARG},
		{ g_bin_name, g_args,    TRUE,  NULL, "simple",               _test_trip_start, TEST_ERRMSG_TRIP_FAILEDSTART},
		{NULL, NULL, 0, NULL, NULL, NULL, NULL}			
	};

	//--------
	// test crawler
	static TTestCase testcase_crawl[] = {
		{ g_bin_name, "-Otrip_action_purge_container -Otrip=trip_container -- -trip_container.s=/tmp", FALSE,  NULL, "bad args",   _test_crawler_simple, TEST_ERRMSG_CRAWLER_BADARGS},
		{ g_bin_name, "-Oaction=action_toto_service -Otrip=trip_container -- -trip_container.s=/tmp",   FALSE,  NULL, "bad_action", _test_crawler_simple, TEST_ERRMSG_CRAWLER_BADACTION},
		{ g_bin_name, "-Otrip=trip_container -- -trip_container.s=/tmp",		 FALSE,  NULL, "missing_action",  _test_crawler_simple, TEST_ERRMSG_CRAWLER_BADACTION},
		{ g_bin_name, "-Otrip=trip_container11 -- -trip_container.s=/tmp",	 FALSE,  NULL, "bad_libtrip",     _test_crawler_simple, TEST_ERRMSG_CRAWLER_BADTRIP},
		{ g_bin_name, "-- -trip_container.s=/tmp",							 FALSE,  NULL, "missing_libtrip", _test_crawler_simple, TEST_ERRMSG_CRAWLER_BADTRIP},
		{ g_bin_name, "-trip_container.s=/tmp",								 FALSE,  NULL, "bad_args",        _test_crawler_simple, TEST_ERRMSG_CRAWLER_BADARGS},
		{ g_bin_name, g_args,		 TRUE,  NULL, "simple",   _test_crawler_simple, TEST_ERRMSG_CRAWLER_FAILEDSTART},
		{NULL, NULL, 0, NULL, NULL, NULL, NULL}
	};


	//---------
	// action
	TTestCaseSrvStub tcss_allok[]  = {{url_srvstub,       SSCMD_ALL_OK_WITHOUTDATA,  "", NULL}, {NULL, 0, "", NULL}};
	TTestCaseSrvStub tcss_allerr[] = {{url_srvstub,      SSCMD_ALL_ERR_WITHOUTDATA, "", NULL}, {NULL, 0, "", NULL}};
	TTestCaseSrvStub tcss_allnone[] = {{url_srvstub,      SSCMD_ALL_NONE, "", NULL}, {NULL, 0, "", NULL}};


	TTestCase testcase_act[] = {
		{ g_bin_name, g_args, FALSE,  &tcss_allerr[0],"metaX/with_error_without_data", _test_action_simple, TEST_ERRMSG_ACTION_MISSINGERR  },
		{ g_bin_name, g_args, FALSE,  &tcss_allok[0], "metaX/timeout",                 _test_action_timeout, TEST_ERRMSG_ACTION_MISSINGERR  },
		{ g_bin_name, g_args, FALSE,  NULL,           "metaX/connect_refused",         _test_action_simple, TEST_ERRMSG_ACTION_MISSINGERR  },
		{ g_bin_name, g_args, TRUE,   &tcss_allok[0], "metaX/no_error_without_data",   _test_action_simple, TEST_ERRMSG_ACTION_FAILEDSRV  },
		//{ g_bin_name, g_args, TRUE,   NULL, "simple", _test_action_simple, TEST_ERRMSG_ACTION_FAILEDSTART},
		{NULL, NULL, 0, NULL, NULL, NULL, NULL}
	};



	//---------
	TTestCase* pT = NULL;
	if (g_str_has_prefix(g_bin_name, "trip_")) {
		pT = &testcase_trip[0];
	} else if (g_str_has_prefix(g_bin_name, "action_")) {
		pT = &testcase_act[0];
	} else if (g_str_has_prefix(g_bin_name, "crawler")) {
		pT = &testcase_crawl[0];
	} else {
		usage(argv[0]);
		exit(1);
	}

	for(;pT->bin_name;pT++) {
		if (!pT->args || (!(strlen(pT->args))))
			continue;

		testcase = g_strdup_printf("/crawler/%s/%s", pT->bin_name, pT->testcase_name);
		g_test_add_data_func(testcase, pT, pT->test);
		g_free(testcase);
	}	


	int rc = g_test_run();

	return rc;
}

