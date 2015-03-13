/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include "expr.h"

static char *__tab[NB_ET] = {
	"VAL_STR_ET",
	"VAL_NUM_ET",
	"UN_NUMSUP_ET",
	"UN_NUMINF_ET",
	"UN_NUMNOT_ET",
	"UN_STRNUM_ET",
	"UN_STRLEN_ET",
	"BIN_STRCMP_ET",
	"BIN_NUMCMP_ET",
	"BIN_NUMEQ_ET",
	"BIN_NUMNEQ_ET",
	"BIN_NUMLT_ET",
	"BIN_NUMLE_ET",
	"BIN_NUMGT_ET",
	"BIN_NUMGE_ET",
	"BIN_NUMADD_ET",
	"BIN_NUMSUB_ET",
	"BIN_NUMMUL_ET",
	"BIN_NUMDIV_ET",
	"BIN_NUMMOD_ET",
	"BIN_NUMAND_ET",
	"BIN_NUMXOR_ET",
	"BIN_NUMOR_ET",
	"ACC_ET"
};

const char *
expr_type2str(enum expr_type_e t)
{
	if (t >= NB_ET)
		return "INVALID_TYPE";

	return __tab[t];
}
