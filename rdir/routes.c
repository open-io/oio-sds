
#line 1 "routes.c.rl"
/*
OpenIO SDS rdir
Copyright (C) 2017-2018 OpenIO SAS, original work as part of OpenIO SDS

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


#line 65 "routes.c.rl"



static const char _rdir_router_s_actions[] = {
	0, 1, 18, 1, 19, 3, 1, 0,
	20, 3, 2, 0, 20, 3, 3, 0,
	20, 3, 4, 0, 20, 3, 5, 0,
	20, 3, 6, 0, 20, 3, 7, 0,
	20, 3, 8, 0, 20, 3, 9, 0,
	20, 3, 10, 0, 20, 3, 11, 0,
	20, 3, 12, 0, 20, 3, 13, 0,
	20, 3, 14, 0, 20, 3, 15, 0,
	20, 3, 16, 0, 20, 3, 17, 0,
	20, 0
};

static const char _rdir_router_s_key_offsets[] = {
	0, 0, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 17,
	18, 19, 20, 21, 28, 29, 30, 31,
	32, 33, 38, 39, 40, 41, 42, 43,
	44, 45, 46, 47, 48, 49, 50, 51,
	52, 53, 54, 55, 56, 57, 58, 59,
	60, 61, 62, 63, 64, 65, 66, 67,
	68, 69, 70, 71, 72, 73, 74, 75,
	76, 77, 78, 79, 83, 84, 85, 86,
	87, 88, 89, 90, 91, 92, 93, 94,
	95, 96, 97, 98, 99, 100, 101, 102,
	103, 104, 105, 106, 107, 108, 109, 110,
	111, 112, 113, 114, 114, 114, 114, 114,
	114, 114, 114, 114, 114, 114, 114, 114,
	114, 114, 114, 114, 0
};

static const char _rdir_router_s_trans_keys[] = {
	99, 115, 118, 111, 110, 102, 105, 103,
	116, 97, 116, 117, 115, 49, 47, 114,
	115, 100, 105, 114, 47, 97, 99, 100,
	102, 109, 112, 115, 100, 109, 105, 110,
	47, 99, 105, 108, 115, 117, 108, 101,
	97, 114, 110, 99, 105, 100, 101, 110,
	116, 111, 99, 107, 104, 111, 119, 110,
	108, 111, 99, 107, 114, 101, 97, 116,
	101, 101, 108, 101, 116, 101, 101, 116,
	99, 104, 101, 116, 97, 50, 47, 99,
	100, 102, 112, 114, 101, 97, 116, 101,
	101, 108, 101, 116, 101, 101, 116, 99,
	104, 117, 115, 104, 117, 115, 104, 116,
	97, 116, 117, 115, 116, 97, 116, 117,
	115, 47, 0
};

static const char _rdir_router_s_single_lengths[] = {
	0, 3, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 2, 1,
	1, 1, 1, 7, 1, 1, 1, 1,
	1, 5, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 4, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0
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
	0, 0, 0, 0, 0
};

static const short _rdir_router_s_index_offsets[] = {
	0, 0, 4, 6, 8, 10, 12, 14,
	16, 18, 20, 22, 24, 26, 28, 31,
	33, 35, 37, 39, 47, 49, 51, 53,
	55, 57, 63, 65, 67, 69, 71, 73,
	75, 77, 79, 81, 83, 85, 87, 89,
	91, 93, 95, 97, 99, 101, 103, 105,
	107, 109, 111, 113, 115, 117, 119, 121,
	123, 125, 127, 129, 131, 133, 135, 137,
	139, 141, 143, 145, 150, 152, 154, 156,
	158, 160, 162, 164, 166, 168, 170, 172,
	174, 176, 178, 180, 182, 184, 186, 188,
	190, 192, 194, 196, 198, 200, 202, 204,
	206, 208, 210, 212, 213, 214, 215, 216,
	217, 218, 219, 220, 221, 222, 223, 224,
	225, 226, 227, 228, 0
};

static const char _rdir_router_s_trans_cond_spaces[] = {
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, 0
};

static const short _rdir_router_s_trans_offsets[] = {
	0, 1, 2, 3, 4, 5, 6, 7,
	8, 9, 10, 11, 12, 13, 14, 15,
	16, 17, 18, 19, 20, 21, 22, 23,
	24, 25, 26, 27, 28, 29, 30, 31,
	32, 33, 34, 35, 36, 37, 38, 39,
	40, 41, 42, 43, 44, 45, 46, 47,
	48, 49, 50, 51, 52, 53, 54, 55,
	56, 57, 58, 59, 60, 61, 62, 63,
	64, 65, 66, 67, 68, 69, 70, 71,
	72, 73, 74, 75, 76, 77, 78, 79,
	80, 81, 82, 83, 84, 85, 86, 87,
	88, 89, 90, 91, 92, 93, 94, 95,
	96, 97, 98, 99, 100, 101, 102, 103,
	104, 105, 106, 107, 108, 109, 110, 111,
	112, 113, 114, 115, 116, 117, 118, 119,
	120, 121, 122, 123, 124, 125, 126, 127,
	128, 129, 130, 131, 132, 133, 134, 135,
	136, 137, 138, 139, 140, 141, 142, 143,
	144, 145, 146, 147, 148, 149, 150, 151,
	152, 153, 154, 155, 156, 157, 158, 159,
	160, 161, 162, 163, 164, 165, 166, 167,
	168, 169, 170, 171, 172, 173, 174, 175,
	176, 177, 178, 179, 180, 181, 182, 183,
	184, 185, 186, 187, 188, 189, 190, 191,
	192, 193, 194, 195, 196, 197, 198, 199,
	200, 201, 202, 203, 204, 205, 206, 207,
	208, 209, 210, 211, 212, 213, 214, 215,
	216, 217, 218, 219, 220, 221, 222, 223,
	224, 225, 226, 227, 228, 229, 230, 231,
	232, 233, 234, 235, 236, 237, 238, 239,
	240, 241, 242, 243, 244, 245, 0
};

static const char _rdir_router_s_trans_lengths[] = {
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 1, 1,
	1, 1, 1, 1, 1, 1, 0
};

static const char _rdir_router_s_cond_keys[] = {
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
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0
};

static const char _rdir_router_s_cond_targs[] = {
	2, 7, 12, 0, 3, 0, 4, 0,
	5, 0, 6, 0, 99, 0, 8, 0,
	9, 0, 10, 0, 11, 0, 100, 0,
	13, 0, 14, 0, 15, 93, 0, 16,
	0, 17, 0, 18, 0, 19, 0, 20,
	48, 53, 58, 62, 85, 88, 0, 21,
	0, 22, 0, 23, 0, 24, 0, 25,
	0, 26, 30, 37, 40, 43, 0, 27,
	0, 28, 0, 29, 0, 101, 0, 31,
	0, 32, 0, 33, 0, 34, 0, 35,
	0, 36, 0, 102, 0, 38, 0, 39,
	0, 103, 0, 41, 0, 42, 0, 104,
	0, 44, 0, 45, 0, 46, 0, 47,
	0, 105, 0, 49, 0, 50, 0, 51,
	0, 52, 0, 106, 0, 54, 0, 55,
	0, 56, 0, 57, 0, 107, 0, 59,
	0, 60, 0, 61, 0, 108, 0, 63,
	0, 64, 0, 65, 0, 66, 0, 67,
	0, 68, 73, 78, 82, 0, 69, 0,
	70, 0, 71, 0, 72, 0, 109, 0,
	74, 0, 75, 0, 76, 0, 77, 0,
	110, 0, 79, 0, 80, 0, 81, 0,
	111, 0, 83, 0, 84, 0, 112, 0,
	86, 0, 87, 0, 113, 0, 89, 0,
	90, 0, 91, 0, 92, 0, 114, 0,
	94, 0, 95, 0, 96, 0, 97, 0,
	115, 0, 1, 0, 98, 98, 98, 98,
	98, 98, 98, 98, 98, 98, 98, 98,
	98, 98, 98, 98, 98, 98, 98, 98,
	98, 98, 98, 98, 98, 98, 98, 98,
	98, 98, 98, 98, 98, 98, 0
};

static const char _rdir_router_s_cond_actions[] = {
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
	0, 0, 0, 0, 9, 5, 33, 29,
	21, 17, 25, 37, 45, 49, 61, 69,
	57, 65, 41, 53, 13, 9, 5, 33,
	29, 21, 17, 25, 37, 45, 49, 61,
	69, 57, 65, 41, 53, 13, 0
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
	0, 0, 1, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0
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
	0, 0, 3, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0
};

static const char _rdir_router_s_eof_trans_indexed[] = {
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
	0, 0, 0, 99, 100, 101, 102, 103,
	104, 105, 106, 107, 108, 109, 110, 111,
	112, 113, 114, 115, 0
};

static const short _rdir_router_s_eof_trans_direct[] = {
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
	0, 0, 0, 230, 231, 232, 233, 234,
	235, 236, 237, 238, 239, 240, 241, 242,
	243, 244, 245, 246, 0
};

static const char _rdir_router_s_nfa_targs[] = {
	0, 0
};

static const char _rdir_router_s_nfa_offsets[] = {
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
	0, 0, 0, 0, 0
};

static const char _rdir_router_s_nfa_push_actions[] = {
	0, 0
};

static const char _rdir_router_s_nfa_pop_trans[] = {
	0, 0
};

static const int rdir_router_s_start = 98;
static const int rdir_router_s_first_final = 98;
static const int rdir_router_s_error = 0;

static const int rdir_router_s_en_route_rdir_request = 98;


#line 68 "routes.c.rl"


static struct rdir_router_result_s _parse(const char *p, const size_t len) {
	struct rdir_router_s parser = {};
	const char* pe = p + len;
	const char* eof = pe;
	struct rdir_router_result_s rc = {};
	rc.result = OIO_RDIR_NOT_MATCHED;
	(void) eof; /* JFS: kept to be ready in case of a FSM change */
	
	{
		parser.cs = (int)rdir_router_s_start;
		parser.ts = 0;
		parser.te = 0;
	}
	
	#line 77 "routes.c.rl"
	
	
	{
		int _klen;
		unsigned int _trans = 0;
		unsigned int _cond = 0;
		const char *_acts;
		unsigned int _nacts;
		const char *_keys;
		const char *_ckeys;
		int _cpc;
		{
			
			if ( p == pe )
			goto _test_eof;
			if ( parser.cs == 0 )
			goto _out;
			_resume:  {
				_acts = ( _rdir_router_s_actions + (_rdir_router_s_from_state_actions[parser.cs]));
				_nacts = (unsigned int)(*( _acts));
				_acts += 1;
				while ( _nacts > 0 ) {
					switch ( (*( _acts)) ) {
						case 19:  {
							{
								#line 1 "NONE"
								{parser.ts = p;}}
							break; }
					}
					_nacts -= 1;
					_acts += 1;
				}
				
				_keys = ( _rdir_router_s_trans_keys + (_rdir_router_s_key_offsets[parser.cs]));
				_trans = (unsigned int)_rdir_router_s_index_offsets[parser.cs];
				
				_klen = (int)_rdir_router_s_single_lengths[parser.cs];
				if ( _klen > 0 ) {
					const char *_lower;
					const char *_mid;
					const char *_upper;
					_lower = _keys;
					_upper = _keys + _klen - 1;
					while ( 1 ) {
						if ( _upper < _lower )
						break;
						
						_mid = _lower + ((_upper-_lower) >> 1);
						if ( ( (*( p))) < (*( _mid)) )
						_upper = _mid - 1;
						else if ( ( (*( p))) > (*( _mid)) )
						_lower = _mid + 1;
						else {
							_trans += (unsigned int)(_mid - _keys);
							goto _match;
						}
					}
					_keys += _klen;
					_trans += (unsigned int)_klen;
				}
				
				_klen = (int)_rdir_router_s_range_lengths[parser.cs];
				if ( _klen > 0 ) {
					const char *_lower;
					const char *_mid;
					const char *_upper;
					_lower = _keys;
					_upper = _keys + (_klen<<1) - 2;
					while ( 1 ) {
						if ( _upper < _lower )
						break;
						
						_mid = _lower + (((_upper-_lower) >> 1) & ~1);
						if ( ( (*( p))) < (*( _mid)) )
						_upper = _mid - 2;
						else if ( ( (*( p))) > (*( _mid + 1)) )
						_lower = _mid + 2;
						else {
							_trans += (unsigned int)((_mid - _keys)>>1);
							goto _match;
						}
					}
					_trans += (unsigned int)_klen;
				}
				
			}
			_match:  {
				_ckeys = ( _rdir_router_s_cond_keys + (_rdir_router_s_trans_offsets[_trans]));
				_klen = (int)_rdir_router_s_trans_lengths[_trans];
				_cond = (unsigned int)_rdir_router_s_trans_offsets[_trans];
				
				_cpc = 0;
				{
					const char *_lower;
					const char *_mid;
					const char *_upper;
					_lower = _ckeys;
					_upper = _ckeys + _klen - 1;
					while ( 1 ) {
						if ( _upper < _lower )
						break;
						
						_mid = _lower + ((_upper-_lower) >> 1);
						if ( _cpc < (int)(*( _mid)) )
						_upper = _mid - 1;
						else if ( _cpc > (int)(*( _mid)) )
						_lower = _mid + 1;
						else {
							_cond += (unsigned int)(_mid - _ckeys);
							goto _match_cond;
						}
					}
					parser.cs = 0;
					goto _again;
				}
			}
			_match_cond:  {
				parser.cs = (int)_rdir_router_s_cond_targs[_cond];
				
				if ( _rdir_router_s_cond_actions[_cond] == 0 )
				goto _again;
				
				_acts = ( _rdir_router_s_actions + (_rdir_router_s_cond_actions[_cond]));
				_nacts = (unsigned int)(*( _acts));
				_acts += 1;
				while ( _nacts > 0 )
				{
					switch ( (*( _acts)) )
					{
						case 0:  {
							{
								#line 38 "routes.c.rl"
								rc.last = p; }
							break; }
						case 1:  {
							{
								#line 40 "routes.c.rl"
								rc.result = OIO_ROUTE_STATUS; }
							break; }
						case 2:  {
							{
								#line 41 "routes.c.rl"
								rc.result = OIO_ROUTE_CONFIG; }
							break; }
						case 3:  {
							{
								#line 42 "routes.c.rl"
								rc.result = OIO_RDIR_STATUS; }
							break; }
						case 4:  {
							{
								#line 43 "routes.c.rl"
								rc.result = OIO_RDIR_ADMIN_SHOW; }
							break; }
						case 5:  {
							{
								#line 44 "routes.c.rl"
								rc.result = OIO_RDIR_ADMIN_LOCK; }
							break; }
						case 6:  {
							{
								#line 45 "routes.c.rl"
								rc.result = OIO_RDIR_ADMIN_UNLOCK; }
							break; }
						case 7:  {
							{
								#line 46 "routes.c.rl"
								rc.result = OIO_RDIR_ADMIN_INCIDENT; }
							break; }
						case 8:  {
							{
								#line 47 "routes.c.rl"
								rc.result = OIO_RDIR_ADMIN_CLEAR; }
							break; }
						case 9:  {
							{
								#line 48 "routes.c.rl"
								rc.result = OIO_RDIR_VOL_CREATE; }
							break; }
						case 10:  {
							{
								#line 49 "routes.c.rl"
								rc.result = OIO_RDIR_VOL_PUSH; }
							break; }
						case 11:  {
							{
								#line 50 "routes.c.rl"
								rc.result = OIO_RDIR_VOL_DELETE; }
							break; }
						case 12:  {
							{
								#line 51 "routes.c.rl"
								rc.result = OIO_RDIR_VOL_FETCH; }
							break; }
						case 13:  {
							{
								#line 52 "routes.c.rl"
								rc.result = OIO_RDIR_VOL_STATUS; }
							break; }
						case 14:  {
							{
								#line 53 "routes.c.rl"
								rc.result = OIO_RDIR_META2_FETCH; }
							break; }
						case 15:  {
							{
								#line 54 "routes.c.rl"
								rc.result = OIO_RDIR_META2_CREATE; }
							break; }
						case 16:  {
							{
								#line 55 "routes.c.rl"
								rc.result = OIO_RDIR_META2_PUSH; }
							break; }
						case 17:  {
							{
								#line 56 "routes.c.rl"
								rc.result = OIO_RDIR_META2_DELETE; }
							break; }
						case 20:  {
							{
								#line 1 "-"
								{parser.te = p;p = p - 1;}}
							break; }
					}
					_nacts -= 1;
					_acts += 1;
				}
				
				
			}
			_again:  {
				_acts = ( _rdir_router_s_actions + (_rdir_router_s_to_state_actions[parser.cs]));
				_nacts = (unsigned int)(*( _acts));
				_acts += 1;
				while ( _nacts > 0 ) {
					switch ( (*( _acts)) ) {
						case 18:  {
							{
								#line 1 "NONE"
								{parser.ts = 0;}}
							break; }
					}
					_nacts -= 1;
					_acts += 1;
				}
				
				if ( parser.cs == 0 )
				goto _out;
				p += 1;
				if ( p != pe )
				goto _resume;
			}
			_test_eof:  { {}
				if ( p == eof )
				{
					if ( _rdir_router_s_eof_trans_direct[parser.cs] > 0 ) {
						_trans = (unsigned int)_rdir_router_s_eof_trans_direct[parser.cs] - 1;
						_cond = (unsigned int)_rdir_router_s_trans_offsets[_trans];
						goto _match_cond;
					}
				}
				
			}
			_out:  { {}
			}
		}
	}
	
	#line 78 "routes.c.rl"
	
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
