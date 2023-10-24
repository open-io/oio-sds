
#line 1 "routes.c.rl"
/*
OpenIO SDS rdir
Copyright (C) 2017-2018 OpenIO SAS, original work as part of OpenIO SDS
Copyright (C) 2021-2023 OVH SAS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>

#include "routes.h"

/** @private */
struct rdir_router_s {
	const char *ts, *te;
	int cs, act;
};

struct rdir_router_result_s {
	const char *last;
	enum rdir_route_e result;
};


#line 68 "routes.c.rl"



#line 43 "routes.c"
static const char _rdir_router_s_actions[] = {
	0, 1, 20, 1, 21, 3, 1, 0, 
	22, 3, 2, 0, 22, 3, 3, 0, 
	22, 3, 4, 0, 22, 3, 5, 0, 
	22, 3, 6, 0, 22, 3, 7, 0, 
	22, 3, 8, 0, 22, 3, 9, 0, 
	22, 3, 10, 0, 22, 3, 11, 0, 
	22, 3, 12, 0, 22, 3, 13, 0, 
	22, 3, 14, 0, 22, 3, 15, 0, 
	22, 3, 16, 0, 22, 3, 17, 0, 
	22, 3, 18, 0, 22, 3, 19, 0, 
	22
};

static const char _rdir_router_s_key_offsets[] = {
	0, 0, 4, 5, 6, 7, 8, 9, 
	10, 11, 12, 13, 14, 15, 16, 17, 
	18, 19, 21, 22, 23, 24, 25, 32, 
	33, 34, 35, 36, 37, 42, 43, 44, 
	45, 46, 47, 48, 49, 50, 51, 52, 
	53, 54, 55, 56, 57, 58, 59, 60, 
	61, 62, 63, 64, 65, 66, 67, 68, 
	69, 70, 71, 72, 73, 74, 75, 76, 
	77, 78, 79, 80, 81, 82, 83, 87, 
	89, 90, 91, 92, 93, 94, 95, 96, 
	97, 98, 99, 100, 101, 102, 103, 104, 
	105, 106, 107, 108, 109, 110, 111, 112, 
	113, 114, 115, 116, 117, 118, 119, 120, 
	121, 122, 122, 122, 122, 122, 122, 122, 
	122, 122, 122, 122, 122, 122, 122, 122, 
	122, 122, 122, 122
};

static const char _rdir_router_s_trans_keys[] = {
	99, 105, 115, 118, 111, 110, 102, 105, 
	103, 110, 102, 111, 116, 97, 116, 117, 
	115, 49, 47, 114, 115, 100, 105, 114, 
	47, 97, 99, 100, 102, 109, 112, 115, 
	100, 109, 105, 110, 47, 99, 105, 108, 
	115, 117, 108, 101, 97, 114, 110, 99, 
	105, 100, 101, 110, 116, 111, 99, 107, 
	104, 111, 119, 110, 108, 111, 99, 107, 
	114, 101, 97, 116, 101, 101, 108, 101, 
	116, 101, 101, 116, 99, 104, 101, 116, 
	97, 50, 47, 99, 100, 102, 112, 111, 
	114, 117, 110, 116, 101, 97, 116, 101, 
	101, 108, 101, 116, 101, 101, 116, 99, 
	104, 117, 115, 104, 117, 115, 104, 116, 
	97, 116, 117, 115, 116, 97, 116, 117, 
	115, 47, 0
};

static const char _rdir_router_s_single_lengths[] = {
	0, 4, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 2, 1, 1, 1, 1, 7, 1, 
	1, 1, 1, 1, 5, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 4, 2, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0
};

static const char _rdir_router_s_range_lengths[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0
};

static const short _rdir_router_s_index_offsets[] = {
	0, 0, 5, 7, 9, 11, 13, 15, 
	17, 19, 21, 23, 25, 27, 29, 31, 
	33, 35, 38, 40, 42, 44, 46, 54, 
	56, 58, 60, 62, 64, 70, 72, 74, 
	76, 78, 80, 82, 84, 86, 88, 90, 
	92, 94, 96, 98, 100, 102, 104, 106, 
	108, 110, 112, 114, 116, 118, 120, 122, 
	124, 126, 128, 130, 132, 134, 136, 138, 
	140, 142, 144, 146, 148, 150, 152, 157, 
	160, 162, 164, 166, 168, 170, 172, 174, 
	176, 178, 180, 182, 184, 186, 188, 190, 
	192, 194, 196, 198, 200, 202, 204, 206, 
	208, 210, 212, 214, 216, 218, 220, 222, 
	224, 226, 227, 228, 229, 230, 231, 232, 
	233, 234, 235, 236, 237, 238, 239, 240, 
	241, 242, 243, 244
};

static const char _rdir_router_s_trans_targs[] = {
	2, 7, 10, 15, 0, 3, 0, 4, 
	0, 5, 0, 6, 0, 105, 0, 8, 
	0, 9, 0, 106, 0, 11, 0, 12, 
	0, 13, 0, 14, 0, 107, 0, 16, 
	0, 17, 0, 18, 99, 0, 19, 0, 
	20, 0, 21, 0, 22, 0, 23, 51, 
	56, 61, 65, 91, 94, 0, 24, 0, 
	25, 0, 26, 0, 27, 0, 28, 0, 
	29, 33, 40, 43, 46, 0, 30, 0, 
	31, 0, 32, 0, 108, 0, 34, 0, 
	35, 0, 36, 0, 37, 0, 38, 0, 
	39, 0, 109, 0, 41, 0, 42, 0, 
	110, 0, 44, 0, 45, 0, 111, 0, 
	47, 0, 48, 0, 49, 0, 50, 0, 
	112, 0, 52, 0, 53, 0, 54, 0, 
	55, 0, 113, 0, 57, 0, 58, 0, 
	59, 0, 60, 0, 114, 0, 62, 0, 
	63, 0, 64, 0, 115, 0, 66, 0, 
	67, 0, 68, 0, 69, 0, 70, 0, 
	71, 79, 84, 88, 0, 72, 75, 0, 
	73, 0, 74, 0, 116, 0, 76, 0, 
	77, 0, 78, 0, 117, 0, 80, 0, 
	81, 0, 82, 0, 83, 0, 118, 0, 
	85, 0, 86, 0, 87, 0, 119, 0, 
	89, 0, 90, 0, 120, 0, 92, 0, 
	93, 0, 121, 0, 95, 0, 96, 0, 
	97, 0, 98, 0, 122, 0, 100, 0, 
	101, 0, 102, 0, 103, 0, 123, 0, 
	1, 0, 104, 104, 104, 104, 104, 104, 
	104, 104, 104, 104, 104, 104, 104, 104, 
	104, 104, 104, 104, 104, 104, 104, 104, 
	104, 104, 104, 104, 104, 104, 104, 104, 
	104, 104, 104, 104, 104, 104, 104, 104, 
	0
};

static const char _rdir_router_s_trans_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 13, 5, 9, 37, 33, 25, 
	21, 29, 41, 49, 53, 65, 69, 77, 
	61, 73, 45, 57, 17, 13, 5, 9, 
	37, 33, 25, 21, 29, 41, 49, 53, 
	65, 69, 77, 61, 73, 45, 57, 17, 
	0
};

static const char _rdir_router_s_to_state_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	1, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0
};

static const char _rdir_router_s_from_state_actions[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	3, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0
};

static const short _rdir_router_s_eof_trans[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 246, 247, 248, 249, 250, 251, 252, 
	253, 254, 255, 256, 257, 258, 259, 260, 
	261, 262, 263, 264
};

static const int rdir_router_s_start = 104;
static const int rdir_router_s_first_final = 104;
static const int rdir_router_s_error = 0;

static const int rdir_router_s_en_route_rdir_request = 104;


#line 71 "routes.c.rl"

static struct rdir_router_result_s _parse(const char *p, const size_t len) {
	struct rdir_router_s parser = {};
	const char* pe = p + len;
	const char* eof = pe;
	struct rdir_router_result_s rc = {};
	rc.result = OIO_RDIR_NOT_MATCHED;
	(void) eof; /* JFS: kept to be ready in case of a FSM change */
	
#line 301 "routes.c"
	{
	 parser.cs = rdir_router_s_start;
	 parser.ts = 0;
	 parser.te = 0;
	 parser.act = 0;
	}

#line 80 "routes.c.rl"
	
#line 311 "routes.c"
	{
	int _klen;
	unsigned int _trans;
	const char *_acts;
	unsigned int _nacts;
	const char *_keys;

	if ( p == pe )
		goto _test_eof;
	if (  parser.cs == 0 )
		goto _out;
_resume:
	_acts = _rdir_router_s_actions + _rdir_router_s_from_state_actions[ parser.cs];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 ) {
		switch ( *_acts++ ) {
	case 21:
#line 1 "NONE"
	{ parser.ts = p;}
	break;
#line 332 "routes.c"
		}
	}

	_keys = _rdir_router_s_trans_keys + _rdir_router_s_key_offsets[ parser.cs];
	_trans = _rdir_router_s_index_offsets[ parser.cs];

	_klen = _rdir_router_s_single_lengths[ parser.cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + _klen - 1;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + ((_upper-_lower) >> 1);
			if ( (*p) < *_mid )
				_upper = _mid - 1;
			else if ( (*p) > *_mid )
				_lower = _mid + 1;
			else {
				_trans += (unsigned int)(_mid - _keys);
				goto _match;
			}
		}
		_keys += _klen;
		_trans += _klen;
	}

	_klen = _rdir_router_s_range_lengths[ parser.cs];
	if ( _klen > 0 ) {
		const char *_lower = _keys;
		const char *_mid;
		const char *_upper = _keys + (_klen<<1) - 2;
		while (1) {
			if ( _upper < _lower )
				break;

			_mid = _lower + (((_upper-_lower) >> 1) & ~1);
			if ( (*p) < _mid[0] )
				_upper = _mid - 2;
			else if ( (*p) > _mid[1] )
				_lower = _mid + 2;
			else {
				_trans += (unsigned int)((_mid - _keys)>>1);
				goto _match;
			}
		}
		_trans += _klen;
	}

_match:
_eof_trans:
	 parser.cs = _rdir_router_s_trans_targs[_trans];

	if ( _rdir_router_s_trans_actions[_trans] == 0 )
		goto _again;

	_acts = _rdir_router_s_actions + _rdir_router_s_trans_actions[_trans];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 )
	{
		switch ( *_acts++ )
		{
	case 0:
#line 39 "routes.c.rl"
	{ rc.last = p; }
	break;
	case 1:
#line 41 "routes.c.rl"
	{ rc.result = OIO_ROUTE_INFO; }
	break;
	case 2:
#line 42 "routes.c.rl"
	{ rc.result = OIO_ROUTE_STATUS; }
	break;
	case 3:
#line 43 "routes.c.rl"
	{ rc.result = OIO_ROUTE_CONFIG; }
	break;
	case 4:
#line 44 "routes.c.rl"
	{ rc.result = OIO_RDIR_STATUS; }
	break;
	case 5:
#line 45 "routes.c.rl"
	{ rc.result = OIO_RDIR_ADMIN_SHOW; }
	break;
	case 6:
#line 46 "routes.c.rl"
	{ rc.result = OIO_RDIR_ADMIN_LOCK; }
	break;
	case 7:
#line 47 "routes.c.rl"
	{ rc.result = OIO_RDIR_ADMIN_UNLOCK; }
	break;
	case 8:
#line 48 "routes.c.rl"
	{ rc.result = OIO_RDIR_ADMIN_INCIDENT; }
	break;
	case 9:
#line 49 "routes.c.rl"
	{ rc.result = OIO_RDIR_ADMIN_CLEAR; }
	break;
	case 10:
#line 50 "routes.c.rl"
	{ rc.result = OIO_RDIR_VOL_CREATE; }
	break;
	case 11:
#line 51 "routes.c.rl"
	{ rc.result = OIO_RDIR_VOL_PUSH; }
	break;
	case 12:
#line 52 "routes.c.rl"
	{ rc.result = OIO_RDIR_VOL_DELETE; }
	break;
	case 13:
#line 53 "routes.c.rl"
	{ rc.result = OIO_RDIR_VOL_FETCH; }
	break;
	case 14:
#line 54 "routes.c.rl"
	{ rc.result = OIO_RDIR_VOL_STATUS; }
	break;
	case 15:
#line 55 "routes.c.rl"
	{ rc.result = OIO_RDIR_META2_FETCH; }
	break;
	case 16:
#line 56 "routes.c.rl"
	{ rc.result = OIO_RDIR_META2_COUNT; }
	break;
	case 17:
#line 57 "routes.c.rl"
	{ rc.result = OIO_RDIR_META2_CREATE; }
	break;
	case 18:
#line 58 "routes.c.rl"
	{ rc.result = OIO_RDIR_META2_PUSH; }
	break;
	case 19:
#line 59 "routes.c.rl"
	{ rc.result = OIO_RDIR_META2_DELETE; }
	break;
	case 22:
#line 66 "routes.c.rl"
	{ parser.te = p;p--;}
	break;
#line 481 "routes.c"
		}
	}

_again:
	_acts = _rdir_router_s_actions + _rdir_router_s_to_state_actions[ parser.cs];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 ) {
		switch ( *_acts++ ) {
	case 20:
#line 1 "NONE"
	{ parser.ts = 0;}
	break;
#line 494 "routes.c"
		}
	}

	if (  parser.cs == 0 )
		goto _out;
	if ( ++p != pe )
		goto _resume;
	_test_eof: {}
	if ( p == eof )
	{
	if ( _rdir_router_s_eof_trans[ parser.cs] > 0 ) {
		_trans = _rdir_router_s_eof_trans[ parser.cs] - 1;
		goto _eof_trans;
	}
	}

	_out: {}
	}

#line 81 "routes.c.rl"
	return rc;
}

enum rdir_route_e oio_rdir_parse_route(const char *p) {
	if (!p)
		return OIO_RDIR_NOT_MATCHED;
	const size_t len = strlen(p);
	struct rdir_router_result_s rc = _parse(p, len);

	/* the FSM embed actions that return, here we are when the parsing fails */
	return (p+len) == rc.last ? rc.result : OIO_RDIR_NOT_MATCHED;
}
