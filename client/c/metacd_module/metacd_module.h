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

#ifndef __METACD_MODULE_H__
# define __METACD_MODULE_H__
# define MSGNAME_METACD_GETM0   "METACD_GETM0"
# define MSGNAME_METACD_GETM1   "METACD_GETM1"
# define MSGNAME_METACD_SET_M1_MASTER "METACD_MASTERM1"
# define MSGNAME_METACD_GETM2   "METACD_GETM2"
# define MSGNAME_METACD_DECACHE "METACD_DECACHE"
# define MSGNAME_METACD_V1_CHUNKS_PUT   "MCD_V1_CHUNKSPUT"
# define MSGNAME_METACD_V1_CHUNKS_GET   "MCD_V1_CHUNKSGET"
# define MSGNAME_METACD_V1_CHUNKS_DEL   "MCD_V1_CHUNKSDEL"
# define MSGNAME_METACD_V1_CHUNKS_FLUSH "MCD_V1_CHUNKSFLUSH"
# define MSGNAME_METACD_V2_CHUNKS_PUT  "MCD_V2_CHUNKSPUT"
# define MSGNAME_METACD_V2_CHUNKS_GET  "MCD_V2_CHUNKSGET"
# define MSGNAME_METACD_V2_CHUNKS_DEL  "MCD_V2_CHUNKSDEL"
# define MSGNAME_METACD_V2_CHUNKS_FLUSH "MCD_V2_CHUNKSFLUSH"
# define MSGKEY_NS  "NS"
# define MSGKEY_CID "CID"
# define MSGKEY_PATH "PATH"

# ifndef KEY_PARAM_CSTO_CNX
#  define KEY_PARAM_CSTO_CNX "timeout.conscience.cnx"
# endif

# ifndef KEY_PARAM_CSTO_REQ
#  define KEY_PARAM_CSTO_REQ "timeout.conscience.req"
# endif

# ifndef KEY_PARAM_META1CACHE_SIZE
#  define KEY_PARAM_META1CACHE_SIZE "meta1_cache_size"
# endif

# ifndef KEY_PARAM_CHUNKSCACHE_SIZE
#  define KEY_PARAM_CHUNKSCACHE_SIZE "chunks_cache_size"
# endif

# ifndef KEY_PARAM_META1CACHE_EXPIRATION
#  define KEY_PARAM_META1CACHE_EXPIRATION "meta1_cache_expiration"
# endif

# ifndef KEY_PARAM_CHUNKSCACHE_EXPIRATION
#  define KEY_PARAM_CHUNKSCACHE_EXPIRATION "chunks_cache_expiration"
# endif

# ifndef KEY_PARAM_CHUNKSCACHE_NOATIME
#  define KEY_PARAM_CHUNKSCACHE_NOATIME "chunks_cache_noatime"
# endif

# ifndef KEY_PARAM_ACCESSLOG
#  define KEY_PARAM_ACCESSLOG "access_log"
# endif

# ifndef DEFAULT_META1CACHE_EXPIRATION
#  define DEFAULT_META1CACHE_EXPIRATION 43200
# endif

# ifndef DEFAULT_CHUNKSCACHE_EXPIRATION
#  define DEFAULT_CHUNKSCACHE_EXPIRATION 7200
# endif

# ifndef DEFAULT_META1CACHE_SIZE
#  define DEFAULT_META1CACHE_SIZE 100000
# endif

# ifndef DEFAULT_CHUNKSCACHE_SIZE
#  define DEFAULT_CHUNKSCACHE_SIZE 10000
# endif

#endif /*__METACD_MODULE_H__*/
