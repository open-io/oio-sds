
#line 1 "routes.c.rl"
/*
OpenIO SDS rdir
Copyright (C) 2017 OpenIO, original work as part of OpenIO SDS

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
    int cs, act, ok;
};


#line 54 "routes.c.rl"



#line 37 "routes.c"
static const char _rdir_router_s_actions[] = {
	0, 1, 13, 1, 14, 3, 1, 0, 
	15, 3, 2, 0, 15, 3, 3, 0, 
	15, 3, 4, 0, 15, 3, 5, 0, 
	15, 3, 6, 0, 15, 3, 7, 0, 
	15, 3, 8, 0, 15, 3, 9, 0, 
	15, 3, 10, 0, 15, 3, 11, 0, 
	15, 3, 12, 0, 15
};

static const char _rdir_router_s_key_offsets[] = {
	0, 0, 2, 3, 4, 5, 6, 7, 
	8, 9, 11, 12, 13, 14, 15, 21, 
	22, 23, 24, 25, 26, 31, 32, 33, 
	34, 35, 36, 37, 38, 39, 40, 41, 
	42, 43, 44, 45, 46, 47, 48, 49, 
	50, 51, 52, 53, 54, 55, 56, 57, 
	58, 59, 60, 61, 62, 63, 64, 65, 
	66, 67, 68, 69, 70, 71, 72, 73, 
	74, 75, 76, 77, 78, 79, 80, 81, 
	81, 81, 81, 81, 81, 81, 81, 81, 
	81, 81, 81
};

static const char _rdir_router_s_trans_keys[] = {
	115, 118, 116, 97, 116, 117, 115, 49, 
	47, 114, 115, 100, 105, 114, 47, 97, 
	99, 100, 102, 112, 115, 100, 109, 105, 
	110, 47, 99, 105, 108, 115, 117, 108, 
	101, 97, 114, 110, 99, 105, 100, 101, 
	110, 116, 111, 99, 107, 104, 111, 119, 
	110, 108, 111, 99, 107, 114, 101, 97, 
	116, 101, 101, 108, 101, 116, 101, 101, 
	116, 99, 104, 117, 115, 104, 116, 97, 
	116, 117, 115, 116, 97, 116, 117, 115, 
	47, 0
};

static const char _rdir_router_s_single_lengths[] = {
	0, 2, 1, 1, 1, 1, 1, 1, 
	1, 2, 1, 1, 1, 1, 6, 1, 
	1, 1, 1, 1, 5, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0
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
	0, 0, 0
};

static const unsigned char _rdir_router_s_index_offsets[] = {
	0, 0, 3, 5, 7, 9, 11, 13, 
	15, 17, 20, 22, 24, 26, 28, 35, 
	37, 39, 41, 43, 45, 51, 53, 55, 
	57, 59, 61, 63, 65, 67, 69, 71, 
	73, 75, 77, 79, 81, 83, 85, 87, 
	89, 91, 93, 95, 97, 99, 101, 103, 
	105, 107, 109, 111, 113, 115, 117, 119, 
	121, 123, 125, 127, 129, 131, 133, 135, 
	137, 139, 141, 143, 145, 147, 149, 151, 
	152, 153, 154, 155, 156, 157, 158, 159, 
	160, 161, 162
};

static const char _rdir_router_s_trans_targs[] = {
	2, 7, 0, 3, 0, 4, 0, 5, 
	0, 6, 0, 71, 0, 8, 0, 9, 
	0, 10, 65, 0, 11, 0, 12, 0, 
	13, 0, 14, 0, 15, 43, 48, 53, 
	57, 60, 0, 16, 0, 17, 0, 18, 
	0, 19, 0, 20, 0, 21, 25, 32, 
	35, 38, 0, 22, 0, 23, 0, 24, 
	0, 72, 0, 26, 0, 27, 0, 28, 
	0, 29, 0, 30, 0, 31, 0, 73, 
	0, 33, 0, 34, 0, 74, 0, 36, 
	0, 37, 0, 75, 0, 39, 0, 40, 
	0, 41, 0, 42, 0, 76, 0, 44, 
	0, 45, 0, 46, 0, 47, 0, 77, 
	0, 49, 0, 50, 0, 51, 0, 52, 
	0, 78, 0, 54, 0, 55, 0, 56, 
	0, 79, 0, 58, 0, 59, 0, 80, 
	0, 61, 0, 62, 0, 63, 0, 64, 
	0, 81, 0, 66, 0, 67, 0, 68, 
	0, 69, 0, 82, 0, 1, 0, 70, 
	70, 70, 70, 70, 70, 70, 70, 70, 
	70, 70, 70, 70, 70, 70, 70, 70, 
	70, 70, 70, 70, 70, 70, 70, 0
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
	0, 0, 0, 0, 0, 0, 0, 5, 
	29, 25, 17, 13, 21, 33, 41, 45, 
	37, 49, 9, 5, 29, 25, 17, 13, 
	21, 33, 41, 45, 37, 49, 9, 0
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
	0, 0, 0, 0, 0, 0, 1, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0
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
	0, 0, 0, 0, 0, 0, 3, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0
};

static const unsigned char _rdir_router_s_eof_trans[] = {
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 164, 
	165, 166, 167, 168, 169, 170, 171, 172, 
	173, 174, 175
};

static const int rdir_router_s_start = 70;
static const int rdir_router_s_first_final = 70;
static const int rdir_router_s_error = 0;

static const int rdir_router_s_en_route_rdir_request = 70;


#line 57 "routes.c.rl"

enum rdir_route_e oio_rdir_parse_route(const char *p) {
    if (!p)
        return OIO_RDIR_NOT_MATCHED;
    const size_t len = strlen(p);
    const char* pe = p + len;
    const char* eof = pe;
    struct rdir_router_s parser;
	enum rdir_route_e result = OIO_RDIR_NOT_MATCHED;

    (void) eof; /* JFS: kept to be ready in case of a FSM change */
    
#line 230 "routes.c"
	{
	 parser.cs = rdir_router_s_start;
	 parser.ts = 0;
	 parser.te = 0;
	 parser.act = 0;
	}

#line 69 "routes.c.rl"
    
#line 240 "routes.c"
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
	case 14:
#line 1 "NONE"
	{ parser.ts = p;}
	break;
#line 261 "routes.c"
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
#line 33 "routes.c.rl"
	{ parser.ok = 1; }
	break;
	case 1:
#line 35 "routes.c.rl"
	{ result = OIO_ROUTE_STATUS; }
	break;
	case 2:
#line 36 "routes.c.rl"
	{ result = OIO_RDIR_STATUS; }
	break;
	case 3:
#line 37 "routes.c.rl"
	{ result = OIO_RDIR_ADMIN_SHOW; }
	break;
	case 4:
#line 38 "routes.c.rl"
	{ result = OIO_RDIR_ADMIN_LOCK; }
	break;
	case 5:
#line 39 "routes.c.rl"
	{ result = OIO_RDIR_ADMIN_UNLOCK; }
	break;
	case 6:
#line 40 "routes.c.rl"
	{ result = OIO_RDIR_ADMIN_INCIDENT; }
	break;
	case 7:
#line 41 "routes.c.rl"
	{ result = OIO_RDIR_ADMIN_CLEAR; }
	break;
	case 8:
#line 42 "routes.c.rl"
	{ result = OIO_RDIR_VOL_CREATE; }
	break;
	case 9:
#line 43 "routes.c.rl"
	{ result = OIO_RDIR_VOL_PUSH; }
	break;
	case 10:
#line 44 "routes.c.rl"
	{ result = OIO_RDIR_VOL_DELETE; }
	break;
	case 11:
#line 45 "routes.c.rl"
	{ result = OIO_RDIR_VOL_FETCH; }
	break;
	case 12:
#line 46 "routes.c.rl"
	{ result = OIO_RDIR_VOL_STATUS; }
	break;
	case 15:
#line 52 "routes.c.rl"
	{ parser.te = p;p--;}
	break;
#line 382 "routes.c"
		}
	}

_again:
	_acts = _rdir_router_s_actions + _rdir_router_s_to_state_actions[ parser.cs];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 ) {
		switch ( *_acts++ ) {
	case 13:
#line 1 "NONE"
	{ parser.ts = 0;}
	break;
#line 395 "routes.c"
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

#line 70 "routes.c.rl"

    /* the FSM embed actions that return, here we are when the parsing fails */
    return p == eof && parser.ok ? result : OIO_RDIR_NOT_MATCHED;
}
