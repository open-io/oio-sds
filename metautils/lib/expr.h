/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__metautils__lib__expr_h
# define OIO_SDS__metautils__lib__expr_h 1

#define EXPR_EVAL_UNDEF 1
#define EXPR_EVAL_DEF 0
#define EXPR_EVAL_ERROR -1

#define CHK_TYPE(t,R) do {\
	if ((t)>=NB_ET) {\
		R;\
	}\
} while (0)

typedef char *(accessor_f) (const char *);

typedef accessor_f *(env_f) (const char *);

struct expr_s;

enum expr_type_e
{
	VAL_STR_ET, VAL_NUM_ET,
	UN_NUMSUP_ET, UN_NUMINF_ET, UN_NUMNOT_ET,
	UN_STRNUM_ET, UN_STRLEN_ET,
	BIN_STRCMP_ET, BIN_NUMCMP_ET,
	BIN_NUMEQ_ET, BIN_NUMNEQ_ET,
	BIN_NUMLT_ET, BIN_NUMLE_ET,
	BIN_NUMGT_ET, BIN_NUMGE_ET,
	BIN_NUMADD_ET, BIN_NUMSUB_ET,
	BIN_NUMMUL_ET, BIN_NUMDIV_ET,
	BIN_NUMMOD_ET,
	BIN_NUMAND_ET, BIN_NUMXOR_ET,
	BIN_NUMOR_ET,
	BIN_ROOT_ET,
	ACC_ET,
	/*last beacon */
	NB_ET
};

union internal_expr_u
{
	double num;
	struct expr_s *unary;
	char *str;
	struct
	{
		char *base;
		char *field;
	} acc;
	struct
	{
		struct expr_s *p1;
		struct expr_s *p2;
	} bin;
};

struct expr_s
{
	enum expr_type_e type;
	union internal_expr_u expr;
};

void expr_clean(struct expr_s *pE);

int expr_parse(const char *pBuf, struct expr_s **pE);

int expr_evaluate(double *pResult, struct expr_s *pExpr, env_f pEnv);

#endif /*OIO_SDS__metautils__lib__expr_h*/
