#ifndef __GS_RAWX_TOOLS_H__
# define __GS_RAWX_TOOLS_H__

#include "src/rawx.h"
#include "src/compression.h"

#define PRINT_DEBUG(FMT,...) \
do { if (flag_verbose) g_printerr("debug: "FMT, ##__VA_ARGS__); } while (0)
 
#define PRINT_ERROR(FMT,...) \
do { if (!flag_quiet) g_printerr("\nerror: "FMT, ##__VA_ARGS__); } while (0)

#define IGNORE_ARG(Arg) { if (!optarg) { PRINT_DEBUG("no argument given to the -%c parameter, ignoring it\r\n", Arg); break; } }

#define DEFAULT_COMPRESSION_BLOCKSIZE 512000

#endif /*__GS_RAWX_TOOLS_H__*/
