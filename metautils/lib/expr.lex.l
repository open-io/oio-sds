%{
#define YY_NO_UNPUT
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "expr.yacc.h"

#include "./expr.h"

#if 0
# define T do { fprintf(stderr,"%s\n",yytext) ; } while(0)
#else
# define T
#endif

%}
%option noinput
%%
[ \t\r\n]*      {}

"num"    { T; return UN_STRNUM_TK; }
"len"    { T; return UN_STRLEN_TK; }
"sup"    { T; return UN_NUMSUP_TK; }
"inf"    { T; return UN_NUMINF_TK; }
"not"    { T; return UN_NUMNOT_TK; }
"xor"    { T; return BIN_NUMXOR_TK; }
"and"    { T; return BIN_NUMAND_TK; }
"or"     { T; return BIN_NUMOR_TK; }
"root"	 { T; return BIN_ROOT_TK; }

[-]?[1-9][0-9]* { T; yylval.n=atof(yytext) ; return VAL_NUM_TK; }
[0]             { T; yylval.n=0 ; return VAL_NUM_TK; }

[<][Ss][>] { T; return BIN_STRCMP_TK; }
[<][Nn][>] { T; return BIN_NUMCMP_TK; }
[!][=]     { T; return BIN_NUMEQ_TK; }
[=][=]     { T; return BIN_NUMNEQ_TK; }
[<][=]     { T; return BIN_NUMLT_TK; }
[>][=]     { T; return BIN_NUMGT_TK; }
[<]        { T; return BIN_NUMLE_TK; }
[>]        { T; return BIN_NUMGE_TK; }
[-]        { T; return BIN_NUMSUB_TK; }
[+]        { T; return BIN_NUMADD_TK; }
[/]        { T; return BIN_NUMDIV_TK; }
[*]        { T; return BIN_NUMMUL_TK; }
[%]        { T; return BIN_NUMMOD_TK; }
[(]        { T; return PAROP_TK ; }
[)]        { T; return PARCL_TK ; }
[.]        { T; return DOT_TK ; }
[,]        { T; return COMA_TK ; }

["][^"]*["]               { T; yylval.s=strdup(yytext+1) ; yylval.s[strlen(yylval.s)-1]='\0' ; return VAL_STR_TK; }

[A-Za-z][-_0-9A-Za-z]* { T; yylval.s=strdup(yytext) ; return ID_TK; }

.                         { T; }
%%

int yywrap(void) {
	return 1;
}

