
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


#line 55 "routes.c.rl"



#line 37 "routes.c"
static const char _rdir_router_s_actions[] = {
	0, 1, 14, 1, 15, 3, 1, 0, 
	16, 3, 2, 0, 16, 3, 3, 0, 
	16, 3, 4, 0, 16, 3, 5, 0, 
	16, 3, 6, 0, 16, 3, 7, 0, 
	16, 3, 8, 0, 16, 3, 9, 0, 
	16, 3, 10, 0, 16, 3, 11, 0, 
	16, 3, 12, 0, 16, 3, 13, 0, 
	16
};

static const char _rdir_router_s_key_offsets[] = {
	0, 0, 3, 4, 5, 6, 7, 8, 
	9, 10, 11, 12, 13, 14, 15, 17, 
	18, 19, 20, 21, 27, 28, 29, 30, 
	31, 32, 37, 38, 39, 40, 41, 42, 
	43, 44, 45, 46, 47, 48, 49, 50, 
	51, 52, 53, 54, 55, 56, 57, 58, 
	59, 60, 61, 62, 63, 64, 65, 66, 
	67, 68, 69, 70, 71, 72, 73, 74, 
	75, 76, 77, 78, 79, 80, 81, 82, 
	83, 84, 85, 86, 87, 87, 87, 87, 
	87, 87, 87, 87, 87, 87, 87, 87, 
	87
};

static const char _rdir_router_s_trans_keys[] = {
	99, 115, 118, 111, 110, 102, 105, 103, 
	116, 97, 116, 117, 115, 49, 47, 114, 
	115, 100, 105, 114, 47, 97, 99, 100, 
	102, 112, 115, 100, 109, 105, 110, 47, 
	99, 105, 108, 115, 117, 108, 101, 97, 
	114, 110, 99, 105, 100, 101, 110, 116, 
	111, 99, 107, 104, 111, 119, 110, 108, 
	111, 99, 107, 114, 101, 97, 116, 101, 
	101, 108, 101, 116, 101, 101, 116, 99, 
	104, 117, 115, 104, 116, 97, 116, 117, 
	115, 116, 97, 116, 117, 115, 47, 0
};

static const char _rdir_router_s_single_lengths[] = {
	0, 3, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 2, 1, 
	1, 1, 1, 6, 1, 1, 1, 1, 
	1, 5, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 1, 1, 1, 1, 
	1, 1, 1, 1, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0
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
	0
};

static const short _rdir_router_s_index_offsets[] = {
	0, 0, 4, 6, 8, 10, 12, 14, 
	16, 18, 20, 22, 24, 26, 28, 31, 
	33, 35, 37, 39, 46, 48, 50, 52, 
	54, 56, 62, 64, 66, 68, 70, 72, 
	74, 76, 78, 80, 82, 84, 86, 88, 
	90, 92, 94, 96, 98, 100, 102, 104, 
	106, 108, 110, 112, 114, 116, 118, 120, 
	122, 124, 126, 128, 130, 132, 134, 136, 
	138, 140, 142, 144, 146, 148, 150, 152, 
	154, 156, 158, 160, 162, 163, 164, 165, 
	166, 167, 168, 169, 170, 171, 172, 173, 
	174
};

static const char _rdir_router_s_trans_targs[] = {
	2, 7, 12, 0, 3, 0, 4, 0, 
	5, 0, 6, 0, 76, 0, 8, 0, 
	9, 0, 10, 0, 11, 0, 77, 0, 
	13, 0, 14, 0, 15, 70, 0, 16, 
	0, 17, 0, 18, 0, 19, 0, 20, 
	48, 53, 58, 62, 65, 0, 21, 0, 
	22, 0, 23, 0, 24, 0, 25, 0, 
	26, 30, 37, 40, 43, 0, 27, 0, 
	28, 0, 29, 0, 78, 0, 31, 0, 
	32, 0, 33, 0, 34, 0, 35, 0, 
	36, 0, 79, 0, 38, 0, 39, 0, 
	80, 0, 41, 0, 42, 0, 81, 0, 
	44, 0, 45, 0, 46, 0, 47, 0, 
	82, 0, 49, 0, 50, 0, 51, 0, 
	52, 0, 83, 0, 54, 0, 55, 0, 
	56, 0, 57, 0, 84, 0, 59, 0, 
	60, 0, 61, 0, 85, 0, 63, 0, 
	64, 0, 86, 0, 66, 0, 67, 0, 
	68, 0, 69, 0, 87, 0, 71, 0, 
	72, 0, 73, 0, 74, 0, 88, 0, 
	1, 0, 75, 75, 75, 75, 75, 75, 
	75, 75, 75, 75, 75, 75, 75, 75, 
	75, 75, 75, 75, 75, 75, 75, 75, 
	75, 75, 75, 75, 0
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
	0, 0, 9, 5, 33, 29, 21, 17, 
	25, 37, 45, 49, 41, 53, 13, 9, 
	5, 33, 29, 21, 17, 25, 37, 45, 
	49, 41, 53, 13, 0
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
	0, 0, 0, 1, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0
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
	0, 0, 0, 3, 0, 0, 0, 0, 
	0, 0, 0, 0, 0, 0, 0, 0, 
	0
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
	0, 0, 0, 0, 176, 177, 178, 179, 
	180, 181, 182, 183, 184, 185, 186, 187, 
	188
};

static const int rdir_router_s_start = 75;
static const int rdir_router_s_first_final = 75;
static const int rdir_router_s_error = 0;

static const int rdir_router_s_en_route_rdir_request = 75;


#line 58 "routes.c.rl"

enum rdir_route_e oio_rdir_parse_route(const char *p) {
    if (!p)
        return OIO_RDIR_NOT_MATCHED;
    const size_t len = strlen(p);
    const char* pe = p + len;
    const char* eof = pe;
    struct rdir_router_s parser;
	enum rdir_route_e result = OIO_RDIR_NOT_MATCHED;

    (void) eof; /* JFS: kept to be ready in case of a FSM change */
    
#line 242 "routes.c"
	{
	 parser.cs = rdir_router_s_start;
	 parser.ts = 0;
	 parser.te = 0;
	 parser.act = 0;
	}

#line 70 "routes.c.rl"
    
#line 252 "routes.c"
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
	case 15:
#line 1 "NONE"
	{ parser.ts = p;}
	break;
#line 273 "routes.c"
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
	{ result = OIO_ROUTE_CONFIG; }
	break;
	case 3:
#line 37 "routes.c.rl"
	{ result = OIO_RDIR_STATUS; }
	break;
	case 4:
#line 38 "routes.c.rl"
	{ result = OIO_RDIR_ADMIN_SHOW; }
	break;
	case 5:
#line 39 "routes.c.rl"
	{ result = OIO_RDIR_ADMIN_LOCK; }
	break;
	case 6:
#line 40 "routes.c.rl"
	{ result = OIO_RDIR_ADMIN_UNLOCK; }
	break;
	case 7:
#line 41 "routes.c.rl"
	{ result = OIO_RDIR_ADMIN_INCIDENT; }
	break;
	case 8:
#line 42 "routes.c.rl"
	{ result = OIO_RDIR_ADMIN_CLEAR; }
	break;
	case 9:
#line 43 "routes.c.rl"
	{ result = OIO_RDIR_VOL_CREATE; }
	break;
	case 10:
#line 44 "routes.c.rl"
	{ result = OIO_RDIR_VOL_PUSH; }
	break;
	case 11:
#line 45 "routes.c.rl"
	{ result = OIO_RDIR_VOL_DELETE; }
	break;
	case 12:
#line 46 "routes.c.rl"
	{ result = OIO_RDIR_VOL_FETCH; }
	break;
	case 13:
#line 47 "routes.c.rl"
	{ result = OIO_RDIR_VOL_STATUS; }
	break;
	case 16:
#line 53 "routes.c.rl"
	{ parser.te = p;p--;}
	break;
#line 398 "routes.c"
		}
	}

_again:
	_acts = _rdir_router_s_actions + _rdir_router_s_to_state_actions[ parser.cs];
	_nacts = (unsigned int) *_acts++;
	while ( _nacts-- > 0 ) {
		switch ( *_acts++ ) {
	case 14:
#line 1 "NONE"
	{ parser.ts = 0;}
	break;
#line 411 "routes.c"
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

#line 71 "routes.c.rl"

    /* the FSM embed actions that return, here we are when the parsing fails */
    return p == eof && parser.ok ? result : OIO_RDIR_NOT_MATCHED;
}
