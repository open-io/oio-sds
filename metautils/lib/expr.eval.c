#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.metautils"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <math.h>

#include "expr.h"
#include "metautils.h"

#if 0
#define FP_EPSILON 0.0000000000001
#define FPcmp(ret,d1,d2) do {\
	if (d1<(d2-FP_EPSILON)) ret=-1;\
	else if (d1>(d2+FP_EPSILON)) ret=1;\
	else ret=0;\
} while (0);
#else
#define FPcmp(ret,d1,d2) do {\
	if (d1<d2) { ret=-1; }\
	else if (d1>d2) { ret=1; }\
	else { ret=0;  }\
} while (0);
#endif

#define EVAL_BINNUM(d1,d2,pE) do {\
	ret = __main_eval(pE->expr.bin.p1, &d1); if (ret!=EXPR_EVAL_DEF) return ret;\
	ret = __main_eval(pE->expr.bin.p2, &d2); if (ret!=EXPR_EVAL_DEF) return ret;\
} while (0)

#define FPBOOL(D) ((D>0.0)||(D<0.0))

int
expr_evaluate(double *pResult, struct expr_s *pExpr, env_f pEnv)
{
	/* Evitons quelques douloureux passages de parametres tres repetitifs
	 * en utilisant quelques fonctions imbriquees. On economisera d'autant
	 * plus d'espace sur la pile. Et c'est bon dans la mesure ou
	 * l'interpretation des expression est recursive */

	int __get_str(struct expr_s *pE, char **ppS)
	{

		if (!ppS || !pE)
			return EXPR_EVAL_ERROR;

		*ppS = NULL;
		CHK_TYPE(pE->type, return EXPR_EVAL_ERROR);

		switch (pE->type) {
		case VAL_STR_ET:
			*ppS = strdup(pE->expr.str);
			return EXPR_EVAL_DEF;
		case VAL_NUM_ET:
		case UN_NUMSUP_ET:
		case UN_NUMINF_ET:
		case UN_NUMNOT_ET:
		case UN_STRNUM_ET:
		case UN_STRLEN_ET:
		case BIN_STRCMP_ET:
		case BIN_NUMCMP_ET:
		case BIN_NUMEQ_ET:
		case BIN_NUMNEQ_ET:
		case BIN_NUMLT_ET:
		case BIN_NUMLE_ET:
		case BIN_NUMGT_ET:
		case BIN_NUMGE_ET:
		case BIN_NUMADD_ET:
		case BIN_NUMSUB_ET:
		case BIN_NUMMUL_ET:
		case BIN_NUMDIV_ET:
		case BIN_NUMMOD_ET:
		case BIN_NUMAND_ET:
		case BIN_NUMXOR_ET:
		case BIN_NUMOR_ET:
		case BIN_ROOT_ET:
		case NB_ET:
			return EXPR_EVAL_UNDEF;
		case ACC_ET:{
				accessor_f *acc = NULL;

				if (!pE->expr.acc.base)
					return EXPR_EVAL_ERROR;
				if (!pE->expr.acc.field)
					return EXPR_EVAL_ERROR;
				acc = pEnv(pE->expr.acc.base);
				if (!acc)
					return EXPR_EVAL_UNDEF;
				*ppS = acc(pE->expr.acc.field);
				if (!(*ppS))
					return EXPR_EVAL_UNDEF;
				return EXPR_EVAL_DEF;
			}
		}

		return EXPR_EVAL_ERROR;
	}

	int __main_eval(struct expr_s *pE, double *pD)
	{
		int ret;

		if (!pE || !pD || !pEnv) {
			return EXPR_EVAL_ERROR;
		}

		CHK_TYPE(pE->type, return EXPR_EVAL_ERROR);

		switch (pE->type) {
		case ACC_ET:
		case VAL_STR_ET:
			{
				char *s;

				ret = __get_str(pE, &s);
				if (ret != EXPR_EVAL_DEF)
					return ret;
				*pD = strlen(s);
				free(s);
				return EXPR_EVAL_DEF;
			}

		case VAL_NUM_ET:
			*pD = pE->expr.num;
			return EXPR_EVAL_DEF;

		case UN_NUMSUP_ET:
			ret = __main_eval(pE->expr.unary, pD);
			if (ret != EXPR_EVAL_DEF)
				return ret;
			*pD = ceil(*pD);
			return EXPR_EVAL_DEF;

		case UN_NUMINF_ET:
			ret = __main_eval(pE->expr.unary, pD);
			if (ret != EXPR_EVAL_DEF)
				return ret;
			*pD = floor(*pD);
			return EXPR_EVAL_DEF;

		case UN_NUMNOT_ET:
			ret = __main_eval(pE->expr.unary, pD);
			if (ret != EXPR_EVAL_DEF)
				return ret;
			*pD = ((int) *pD) ? 0 : 1;
			return EXPR_EVAL_DEF;

		case UN_STRNUM_ET:{
				char *pEnd = NULL;
				char *ppS = NULL;
				struct expr_s *pUnary = pE->expr.unary;

				if (!pUnary)
					return EXPR_EVAL_ERROR;
				if (pUnary->type == VAL_NUM_ET) {
					TRACE("num arg is type VAL_NUM_ET");
					*pD = pUnary->expr.num;
				}
				else if (pUnary->type == VAL_STR_ET) {
					TRACE("num arg is type VAL_STR_ET");
					*pD = strtod(pUnary->expr.str, &pEnd);
					if (pEnd == pUnary->expr.str)
						return EXPR_EVAL_UNDEF;
				}
				else if (pUnary->type == ACC_ET) {
					TRACE("num arg is type ACC_ET");
					accessor_f *acc = NULL;

					if (!pUnary->expr.acc.base)
						return EXPR_EVAL_ERROR;
					if (!pUnary->expr.acc.field)
						return EXPR_EVAL_ERROR;
					acc = pEnv(pUnary->expr.acc.base);
					if (!acc)
						return EXPR_EVAL_UNDEF;
					ppS = acc(pUnary->expr.acc.field);
					if (!ppS)
						return EXPR_EVAL_UNDEF;
					*pD = strtod(ppS, &pEnd);
					if (pEnd == ppS)
						return EXPR_EVAL_UNDEF;
					free(ppS);
					return EXPR_EVAL_DEF;
				}
				else {
					TRACE("num arg is type expr");
					return __main_eval(pUnary, pD);
				}

				/*TODO test if there remains some characters */
				return EXPR_EVAL_DEF;
			}

		case UN_STRLEN_ET:{
				char *s = NULL;

				ret = __get_str(pE->expr.unary, &s);
				if (ret != EXPR_EVAL_DEF)
					return ret;
				*pD = strlen(s);
				free(s);
				return EXPR_EVAL_DEF;
			}

		case BIN_STRCMP_ET:{
				char *s1 = NULL, *s2 = NULL;

				if (!pE->expr.bin.p1)
					return EXPR_EVAL_ERROR;
				if (!pE->expr.bin.p2)
					return EXPR_EVAL_ERROR;
				ret = __get_str(pE->expr.bin.p1, &s1);
				if (ret != EXPR_EVAL_DEF)
					return ret;
				ret = __get_str(pE->expr.bin.p2, &s2);
				if (ret != EXPR_EVAL_DEF) {
					free(s1);
					return ret;
				}
				*pD = (strcmp(s1, s2) == 0);
				free(s1);
				if (s2 != s1)
					free(s2);
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMCMP_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				FPcmp(*pD, d1, d2);
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMEQ_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				FPcmp(ret, d1, d2);
				*pD = (ret == 0);
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMNEQ_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				FPcmp(ret, d1, d2);
				*pD = (ret != 0);
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMLT_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				FPcmp(ret, d1, d2);
				*pD = (ret < 0);
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMLE_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				FPcmp(ret, d1, d2);
				*pD = (ret <= 0);
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMGT_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				FPcmp(ret, d1, d2);
				*pD = (ret > 0);
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMGE_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				FPcmp(ret, d1, d2);
				*pD = (ret >= 0);
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMADD_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				*pD = d1 + d2;
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMSUB_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				*pD = d1 - d2;
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMMUL_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				*pD = d1 * d2;
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMDIV_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				FPcmp(ret, d2, 0);
				if (ret == 0)
					return EXPR_EVAL_DEF;
				*pD = d1 / d2;
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMMOD_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				FPcmp(ret, d1, 0);
				if (ret < 0)
					return EXPR_EVAL_DEF;
				FPcmp(ret, d2, 0);
				if (ret < 0)
					return EXPR_EVAL_DEF;
				*pD = (double) ((int) d1 % (int) d2);
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMAND_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				*pD = FPBOOL(d1) && FPBOOL(d2);
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMXOR_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				*pD = (int) d1 ^ (int) d2;
				return EXPR_EVAL_DEF;
			}

		case BIN_NUMOR_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				*pD = d1 + d2;
				return EXPR_EVAL_DEF;
			}

		case BIN_ROOT_ET:{
				double d1 = 0, d2 = 0;

				EVAL_BINNUM(d1, d2, pE);
				TRACE("root with args [%f]/[%f]", d1, d2);
				FPcmp(ret, d1, 0);
				if (ret == 0)
					return EXPR_EVAL_UNDEF;
				FPcmp(ret, d2, 0);
				if (ret == 0) {
					*pD = 0.0;
					return EXPR_EVAL_DEF;
				}
				*pD = pow(d2, 1 / d1);
				TRACE("root with args [%f]/[%f] return result [%f]", d1, d2, *pD);
				return EXPR_EVAL_DEF;
			}
		case NB_ET:
			break;
		}

		return EXPR_EVAL_UNDEF;
	}

	/* 
	 * Corps de la fonction, bous appelons le point d'entree
	 * de la recursion (__main_eval) apres une verification
	 * des parametres de la fonction.
	 */

	if (!pResult || !pExpr || !pEnv)
		return EXPR_EVAL_ERROR;

	return __main_eval(pExpr, pResult);
}
