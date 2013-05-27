/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __GS_RAWX_TOOLS_H__
# define __GS_RAWX_TOOLS_H__

#include "../src/rawx.h"
#include "../src/compression.h"

#define PRINT_DEBUG(FMT,...) \
do { if (flag_verbose) g_printerr("debug: "FMT, ##__VA_ARGS__); } while (0)
 
#define PRINT_ERROR(FMT,...) \
do { if (!flag_quiet) g_printerr("\nerror: "FMT, ##__VA_ARGS__); } while (0)

#define IGNORE_ARG(Arg) { if (!optarg) { PRINT_DEBUG("no argument given to the -%c parameter, ignoring it\r\n", Arg); break; } }

#define DEFAULT_COMPRESSION_BLOCKSIZE 512000

#endif /*__GS_RAWX_TOOLS_H__*/
